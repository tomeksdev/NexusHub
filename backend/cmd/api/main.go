// Command api runs the NexusHub HTTP API server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/auth"
	"github.com/tomeksdev/NexusHub/backend/internal/config"
	"github.com/tomeksdev/NexusHub/backend/internal/crypto"
	"github.com/tomeksdev/NexusHub/backend/internal/db"
	"github.com/tomeksdev/NexusHub/backend/internal/handler"
	"github.com/tomeksdev/NexusHub/backend/internal/metrics"
	"github.com/tomeksdev/NexusHub/backend/internal/middleware"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

// Populated via -ldflags -X at build time. Falling back to "dev" keeps
// `go run ./cmd/api` readable in development.
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("api exited with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	gin.SetMode(cfg.GinMode)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	metrics.SetBuildInfo(buildVersion, buildCommit)
	metrics.RegisterPoolCollector(pool)

	jwtIssuer, err := auth.NewJWTIssuer(cfg.JWTSecret, cfg.JWTAccessExpiry)
	if err != nil {
		return fmt.Errorf("jwt issuer: %w", err)
	}

	aead, err := crypto.NewFromBase64(cfg.PeerKeyEncryptionKey)
	if err != nil {
		return fmt.Errorf("peer key encryption: %w", err)
	}

	ifaceRepo := repository.NewInterfaceRepo(pool)
	peerRepo := repository.NewPeerRepo(pool)
	ruleRepo := repository.NewRuleRepo(pool)

	// Try to open a netlink client. If we can't (no CAP_NET_ADMIN, no
	// kernel module, containerised dev env), skip kernel sync and run
	// DB-only — the handlers and reconciler are both nil-safe on wgClient.
	var wgClient wg.Client
	if kc, werr := wg.NewKernelClient(); werr != nil {
		slog.Warn("wgctrl unavailable — running DB-only", "err", werr)
	} else {
		wgClient = kc
		defer kc.Close()
		mode := wg.DetectMode(kc, "")
		slog.Info("wireguard mode detected", "mode", string(mode))

		// Startup reconciliation: converge the kernel to DB state. Errors
		// are logged per-interface and do not block API startup.
		if dbs, rerr := loadDBInterfaces(ctx, aead, ifaceRepo, peerRepo); rerr != nil {
			slog.Error("reconcile: load db state", "err", rerr)
		} else {
			wg.ReconcileStartup(ctx, wgClient, slog.Default(), dbs)
		}
	}

	router := handler.NewRouter(handler.Deps{
		JWTIssuer:         jwtIssuer,
		Users:             repository.NewUserRepo(pool),
		Sessions:          repository.NewSessionRepo(pool),
		Audit:             repository.NewAuditRepo(pool),
		Interfaces:        ifaceRepo,
		Peers:             peerRepo,
		Rules:             ruleRepo,
		AEAD:              aead,
		RefreshTTL:        cfg.JWTRefreshExpiry,
		WG:                wgClient,
		DefaultWGEndpoint: cfg.WGEndpoint,
		LoginLimit: middleware.RateLimitConfig{
			Name:      "login",
			PerMinute: cfg.RateLimitLoginPerMinute,
			Burst:     cfg.RateLimitLoginBurst,
		},
		RefreshLimit: middleware.RateLimitConfig{
			Name:      "refresh",
			PerMinute: cfg.RateLimitRefreshPerMinute,
			Burst:     cfg.RateLimitRefreshBurst,
		},
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("api listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		slog.Info("api shutdown requested")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	slog.Info("api stopped cleanly")
	return nil
}

// loadDBInterfaces is the glue between the repository layer and the wg
// reconciler's plain-data spec type. It decrypts every interface private
// key and every active peer PSK before handing them off — the reconciler
// only speaks raw bytes. Lives here rather than in wg/ or repository/ to
// keep those packages free of a mutual import.
func loadDBInterfaces(
	ctx context.Context,
	aead *crypto.AEAD,
	ifaces *repository.InterfaceRepo,
	peers *repository.PeerRepo,
) ([]wg.DBInterface, error) {
	rows, err := ifaces.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]wg.DBInterface, 0, len(rows))
	for _, iface := range rows {
		priv, err := aead.Open(iface.PrivateKey, []byte("wg_interfaces.private_key"))
		if err != nil {
			slog.Warn("reconcile: skip interface, decrypt failed",
				"iface", iface.Name, "err", err)
			continue
		}
		dbi := wg.DBInterface{
			Name: iface.Name, PrivateKey: priv, ListenPort: iface.ListenPort,
		}
		peerRows, err := peers.ListByInterface(ctx, iface.ID)
		if err != nil {
			slog.Warn("reconcile: skip interface, list peers failed",
				"iface", iface.Name, "err", err)
			continue
		}
		for _, p := range peerRows {
			dp := wg.DBPeer{
				PublicKey:  p.PublicKey,
				Endpoint:   p.Endpoint,
				AllowedIPs: p.AllowedIPs,
				AssignedIP: p.AssignedIP,
				Keepalive:  p.PersistentKeepalive,
			}
			if sealed, err := peers.ActivePSK(ctx, p.ID); err == nil && sealed != nil {
				raw, oerr := aead.Open(sealed, []byte("wg_peer_preshared_keys.preshared_key"))
				if oerr != nil {
					slog.Warn("reconcile: skip psk, decrypt failed",
						"peer", p.PublicKey, "err", oerr)
				} else {
					dp.PresharedKey = raw
				}
			}
			dbi.Peers = append(dbi.Peers, dp)
		}
		out = append(out, dbi)
	}
	return out, nil
}

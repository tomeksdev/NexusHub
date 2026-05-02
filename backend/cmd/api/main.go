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

	"github.com/tomeksdev/NexusHub/backend/internal/audit"
	"github.com/tomeksdev/NexusHub/backend/internal/auth"
	"github.com/tomeksdev/NexusHub/backend/internal/config"
	"github.com/tomeksdev/NexusHub/backend/internal/crypto"
	"github.com/tomeksdev/NexusHub/backend/internal/db"
	baseebpf "github.com/tomeksdev/NexusHub/backend/internal/ebpf"
	"github.com/tomeksdev/NexusHub/backend/internal/handler"
	"github.com/tomeksdev/NexusHub/backend/internal/metrics"
	"github.com/tomeksdev/NexusHub/backend/internal/middleware"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/backend/internal/tracing"
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

	// Stand tracing up before the pool so query spans are wired from
	// the first connection ping. When OTEL_EXPORTER_OTLP_ENDPOINT is
	// unset, tracing.Init returns a no-op shutdown and the global
	// provider stays at otel's noop — every span call goes nowhere.
	shutdownTracing, err := tracing.Init(ctx, tracing.Config{Version: buildVersion})
	if err != nil {
		return fmt.Errorf("tracing init: %w", err)
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(flushCtx); err != nil {
			slog.Warn("tracing shutdown", "err", err)
		}
	}()

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
	auditRepo := repository.NewAuditRepo(pool)

	// Start the audit retention loop. Zero AuditRetentionDays (or
	// a negative value) disables pruning — the loop exits
	// immediately. The goroutine shuts down on ctx cancellation.
	go audit.RunRetentionLoop(ctx, auditRepo, audit.RetentionConfig{
		Retention: time.Duration(cfg.AuditRetentionDays) * 24 * time.Hour,
		Interval:  cfg.AuditRetentionScan,
	}, slog.Default())

	// Try to open a netlink client. If we can't (no CAP_NET_ADMIN, no
	// kernel module, containerised dev env), skip kernel sync and run
	// DB-only — the handlers and reconciler are both nil-safe on wgClient.
	var wgClient wg.Client
	// linkManager is the rtnetlink side. Cheap to construct (no
	// resources held until called) so we always wire it; the operator
	// may have run NexusHub in an env without CAP_NET_ADMIN, in which
	// case the per-call netlink syscalls fail and the handlers log
	// without aborting.
	linkManager := wg.NewNetlinkManager()
	// wgIfaceNames is the list of DB-known WireGuard interface names
	// after the startup reconcile. eBPF startup uses it to auto-attach
	// TC (one program per interface) without an env var.
	var wgIfaceNames []string
	if kc, werr := wg.NewKernelClient(); werr != nil {
		slog.Warn("wgctrl unavailable — running DB-only", "err", werr)
	} else {
		wgClient = kc
		defer func() { _ = kc.Close() }()
		mode := wg.DetectMode(kc, "")
		slog.Info("wireguard mode detected", "mode", string(mode))

		// Startup reconciliation: converge the kernel to DB state. Errors
		// are logged per-interface and do not block API startup.
		if dbs, rerr := loadDBInterfaces(ctx, aead, ifaceRepo, peerRepo); rerr != nil {
			slog.Error("reconcile: load db state", "err", rerr)
		} else {
			wg.ReconcileStartup(ctx, wgClient, linkManager, slog.Default(), dbs)
			// Register the WG Prometheus collector with the interfaces
			// we just reconciled. Interfaces added at runtime will not
			// surface until restart — that matches the reconciler model
			// where startup is the alignment point.
			wgIfaceNames = make([]string, 0, len(dbs))
			for _, d := range dbs {
				wgIfaceNames = append(wgIfaceNames, d.Name)
			}
			if len(wgIfaceNames) > 0 {
				metrics.Registry.MustRegister(wg.NewWGCollector(wgClient, wgIfaceNames, slog.Default()))
			}
			// Background poller writes live counters back to the DB
			// every 30s so a freshly-opened Peers page shows non-zero
			// rx/tx and current handshake without waiting for an SSE
			// tick. Errors are logged and swallowed — the SSE stream
			// is the real-time path; this is the page-load fallback.
			go runPeerStatsPoller(ctx, wgClient, peerRepo, wgIfaceNames, slog.Default())
		}
	}

	// eBPF kernel runtime. Loads the bpf2go-generated spec, attaches
	// optional hooks, starts the metrics + log pipelines. On hosts
	// without CAP_BPF (or when bpf2go produced no usable spec) the
	// returned stack carries a NoopSyncer so the handlers see a
	// consistent interface either way.
	connLogRepo := repository.NewConnectionLogRepo(pool)
	// TC interfaces: every WG iface from the DB, plus the operator
	// override if set (de-duped inside startEBPF). XDP stays
	// env-driven because the WAN NIC isn't something the API can
	// derive safely.
	tcIfaces := append([]string(nil), wgIfaceNames...)
	if extra := tcInterfaceFromEnv(); extra != "" {
		tcIfaces = append(tcIfaces, extra)
	}
	ebpfStk := startEBPF(ctx, connLogRepo,
		xdpInterfaceFromEnv(), tcIfaces, slog.Default())
	defer ebpfStk.Close()

	// Seed the kernel maps from the active rules in PostgreSQL so the
	// datapath enforces what the DB says it should — without this,
	// every restart leaves the kernel empty until the operator
	// re-touches each rule via the API. Errors are logged and
	// swallowed; the handlers still work, the kernel just trails the
	// DB until next manual sync.
	if active, err := ruleRepo.ActiveSnapshot(ctx); err != nil {
		slog.Warn("ebpf rule snapshot failed — kernel will trail DB", "err", err)
	} else if len(active) > 0 {
		syncRules := make([]baseebpf.Rule, 0, len(active))
		for i := range active {
			syncRules = append(syncRules, handler.ToSyncRule(&active[i]))
		}
		if err := ebpfStk.syncer.Reconcile(ctx, syncRules); err != nil {
			slog.Warn("ebpf rule reconcile at startup failed", "err", err, "n", len(syncRules))
		} else {
			slog.Info("ebpf rules reconciled to kernel", "count", len(syncRules))
		}
	}

	router := handler.NewRouter(handler.Deps{
		JWTIssuer:         jwtIssuer,
		Users:             repository.NewUserRepo(pool),
		Sessions:          repository.NewSessionRepo(pool),
		Audit:             auditRepo,
		Interfaces:        ifaceRepo,
		Peers:             peerRepo,
		Rules:             ruleRepo,
		AEAD:              aead,
		RefreshTTL:        cfg.JWTRefreshExpiry,
		EBPFSync:          ebpfStk.syncer,
		WG:                wgClient,
		WGLinks:           linkManager,
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

// runPeerStatsPoller bridges the live WG kernel device state into the
// wg_peers table on a 30 s cadence. It exists so a freshly-opened
// admin page reflects current handshake / RX / TX without waiting for
// the SSE stream to deliver its first delta — matching what
// `wg show <iface> dump` would show. Errors are logged and the loop
// continues; a transient netlink hiccup must not stop the poller for
// good.
func runPeerStatsPoller(
	ctx context.Context,
	client wg.Client,
	peers *repository.PeerRepo,
	ifaces []string,
	log *slog.Logger,
) {
	if client == nil || peers == nil || len(ifaces) == 0 {
		return
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	// Run once eagerly so a slow first tick doesn't make the very
	// first page load wait 30 s for non-zero values.
	pollAndWritePeerStats(ctx, client, peers, ifaces, log)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pollAndWritePeerStats(ctx, client, peers, ifaces, log)
		}
	}
}

func pollAndWritePeerStats(
	ctx context.Context,
	client wg.Client,
	peers *repository.PeerRepo,
	ifaces []string,
	log *slog.Logger,
) {
	var batch []repository.PeerLiveStats
	for _, name := range ifaces {
		dev, err := client.Device(name)
		if err != nil || dev == nil {
			continue
		}
		for _, p := range dev.Peers {
			batch = append(batch, repository.PeerLiveStats{
				PublicKey:     p.PublicKey,
				LastHandshake: p.LastHandshake,
				RxBytes:       p.RxBytes,
				TxBytes:       p.TxBytes,
			})
		}
	}
	if len(batch) == 0 {
		return
	}
	if err := peers.UpsertLiveStats(ctx, batch); err != nil {
		log.Warn("peer stats poll: upsert failed", "err", err, "rows", len(batch))
	}
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
			Address: iface.Address,
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

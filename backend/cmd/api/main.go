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

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/auth"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/config"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/db"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/handler"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
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

	jwtIssuer, err := auth.NewJWTIssuer(cfg.JWTSecret, cfg.JWTAccessExpiry)
	if err != nil {
		return fmt.Errorf("jwt issuer: %w", err)
	}

	router := handler.NewRouter(handler.Deps{
		JWTIssuer:  jwtIssuer,
		Users:      repository.NewUserRepo(pool),
		Sessions:   repository.NewSessionRepo(pool),
		Audit:      repository.NewAuditRepo(pool),
		RefreshTTL: cfg.JWTRefreshExpiry,
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

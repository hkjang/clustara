package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"clustara/internal/config"
	"clustara/internal/proxy"
	"clustara/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	db, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		slog.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		slog.Error("migrate database", "error", err)
		os.Exit(1)
	}

	logger := store.NewAsyncLogger(db, cfg.Logging.QueueSize, cfg.Logging.FallbackPath)
	logger.Start()
	defer logger.Stop(context.Background())

	retention := store.NewRetentionWorker(db, cfg.Retention)
	retention.Start()
	defer retention.Stop()

	srv, err := proxy.NewServer(cfg, db, logger, retention)
	if err != nil {
		slog.Error("create proxy server", "error", err)
		os.Exit(1)
	}
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	var reconciler *proxy.K8sRolloutReconciler
	var reaper *proxy.K8sTerminalSessionReaper
	if cfg.Workers.RolloutReconcilerEnabled {
		reconciler = srv.StartK8sRolloutReconciler(workerCtx, proxy.K8sRolloutReconcilerOptions{
			OwnerID:    cfg.Workers.OwnerID,
			Interval:   cfg.Workers.RolloutInterval,
			LeaseTTL:   cfg.Workers.RolloutLeaseTTL,
			BatchSize:  cfg.Workers.RolloutBatchSize,
			MaxBackoff: cfg.Workers.RolloutMaxBackoff,
		})
		slog.Info("k8s rollout reconciler started", "owner_id", cfg.Workers.OwnerID,
			"interval", cfg.Workers.RolloutInterval, "lease_ttl", cfg.Workers.RolloutLeaseTTL)
	} else {
		slog.Warn("k8s rollout reconciler disabled; rollouts will not converge without an attached browser session")
	}
	if cfg.Workers.TerminalReaperEnabled {
		reaper = srv.StartK8sTerminalSessionReaper(workerCtx, proxy.K8sTerminalSessionReaperOptions{
			Interval:   cfg.Workers.TerminalReaperInterval,
			BatchSize:  cfg.Workers.TerminalReaperBatchSize,
			MaxBackoff: cfg.Workers.TerminalReaperBackoff,
		})
		slog.Info("k8s terminal session reaper started", "interval", cfg.Workers.TerminalReaperInterval)
	} else {
		slog.Warn("k8s terminal session reaper disabled; stale exec sessions will not be expired")
	}

	alerts := proxy.NewAlertWorker(db, srv.MetricsHandle(), 60*time.Second)
	srv.AttachAlertWorker(alerts)
	alerts.Start()
	defer alerts.Stop()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("Clustara listening", "addr", cfg.ListenAddr, "database", cfg.Database.Driver)
		errCh <- httpServer.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		slog.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}
	// Cancel first, then wait: an in-flight reconcile tick must be allowed to
	// finish so it releases its cross-replica lease instead of leaving the
	// rollout blocked until the lease TTL expires.
	stopWorkers()
	if !reconciler.Stop(cfg.Workers.ShutdownTimeout) {
		slog.Warn("k8s rollout reconciler did not stop in time; its lease expires after the TTL",
			"timeout", cfg.Workers.ShutdownTimeout, "lease_ttl", cfg.Workers.RolloutLeaseTTL)
	}
	if !reaper.Stop(cfg.Workers.ShutdownTimeout) {
		slog.Warn("k8s terminal session reaper did not stop in time", "timeout", cfg.Workers.ShutdownTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

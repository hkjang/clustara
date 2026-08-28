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
	os.Exit(run())
}

// run holds the entire process lifecycle and reports the exit code, so that
// every exit path unwinds the deferred cleanup below it.
//
// main must never call os.Exit itself once a resource has been registered for
// cleanup, and neither may run: os.Exit skips deferred functions, and
// logger.Stop is the only thing that flushes the async logger's in-memory
// queue. Records sitting in that queue — request and audit rows — exist
// nowhere else, so an os.Exit anywhere below silently destroys them.
// TestMainDoesNotExitPastCleanup pins this.
func run() int {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		return 1
	}

	db, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		slog.Error("open database", "error", err)
		return 1
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		slog.Error("migrate database", "error", err)
		return 1
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
		return 1
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

	exitCode := 0
	select {
	case sig := <-stop:
		slog.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
			exitCode = 1
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

	drainCtx, cancelDrain := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancelDrain()
	if err := httpServer.Shutdown(drainCtx); err != nil {
		// Fall through rather than exiting. Outliving the drain window is an
		// ordinary outcome here, not a corrupt state: HTTP_WRITE_TIMEOUT
		// defaults to 10 minutes so that chat and log streams can be
		// long-lived, while HTTP_SHUTDOWN_TIMEOUT defaults to 15 seconds to
		// fit inside a pod's termination grace period. Abandoning cleanup on
		// this path would drop the queued audit records belonging to the very
		// requests that were still in flight.
		slog.Error("graceful shutdown timed out; releasing resources anyway",
			"error", err, "timeout", cfg.HTTP.ShutdownTimeout, "write_timeout", cfg.HTTP.WriteTimeout)
		exitCode = 1
	}
	// Stop the server's polling schedulers before the deferred db.Close runs;
	// otherwise they keep querying a closed store for the rest of the process.
	// This gets its own budget because drainCtx may already be expired.
	stopCtx, cancelStop := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancelStop()
	if err := srv.Shutdown(stopCtx); err != nil {
		slog.Warn("background schedulers did not stop cleanly", "error", err)
	}
	return exitCode
}

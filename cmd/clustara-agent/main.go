package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"clustara/internal/agent"
)

func main() {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		slog.Error("invalid clustara-agent config", "error", err)
		os.Exit(2)
	}
	runner, err := agent.NewRunner(cfg)
	if err != nil {
		slog.Error("create clustara-agent", "error", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("clustara-agent stopped", "error", err)
		os.Exit(1)
	}
}

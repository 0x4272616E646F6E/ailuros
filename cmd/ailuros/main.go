package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x4272616E646F6E/ailuros/internal/app"
	"github.com/0x4272616E646F6E/ailuros/internal/config"
	"github.com/0x4272616E646F6E/ailuros/internal/telemetry"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ailuros: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.Load(os.LookupEnv, os.ReadFile)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	shutdownTracing, err := telemetry.SetupTracing(ctx)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(sctx)
	}()
	a, err := app.New(cfg, app.Options{})
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

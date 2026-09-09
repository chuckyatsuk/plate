// Command plate is Plate's single binary with two commands (spec Q4): `plate
// serve` (the API) and `plate work` (the worker). Splitting them from day one —
// same binary, different command — is what keeps the API's HA profile and the
// worker's fat, retryable, CPU-bound profile from contaminating each other.
//
// Phase 1 (spec §8) is the read path only: `serve` runs; `work` is a stub that
// refuses, so the shape exists but no worker is claimed to work yet.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chuckyatsuk/plate/internal/service"
	"github.com/chuckyatsuk/plate/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: plate <serve|work>")
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)) // structured logs to stdout (twelve-factor)

	switch os.Args[1] {
	case "serve":
		if err := serve(log); err != nil {
			log.Error("serve failed", "err", err)
			os.Exit(1)
		}
	case "work":
		// Phase 1 has no worker (spec §8). The command exists so the two-process
		// shape is real from day one, but it refuses rather than pretending.
		fmt.Fprintln(os.Stderr, "plate work: the worker is Phase 2 (spec §8); not implemented in the read-path build.")
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "plate: unknown command %q (want serve|work)\n", os.Args[1])
		os.Exit(2)
	}
}

func serve(log *slog.Logger) error {
	ctx := context.Background()

	cfg, err := service.LoadEnv()
	if err != nil {
		return err
	}

	// Run migrations at boot — the SAME migrations the test container runs, so
	// there is one schema and no drift (spec §6).
	if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	// Write-path deps (storage + prober) are opt-in by config: absent R2 config
	// means a read-path-only deployment (the write endpoints answer 501).
	sc, err := service.LoadStorage(ctx)
	if err != nil {
		return err
	}

	svc := service.New(service.Config{
		Store:          st,
		Verifier:       cfg.Verifier,
		URLs:           cfg.URLs,
		Storage:        sc.Storage,
		Prober:         sc.Prober,
		UploadTTL:      sc.UploadTTL,
		UploadMaxBytes: sc.UploadMaxBytes,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           svc.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful SIGTERM shutdown (K8s-ready, spec Q4).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Info("plate serve", "addr", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

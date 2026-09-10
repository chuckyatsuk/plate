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
	"github.com/chuckyatsuk/plate/internal/worker"
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
		if err := work(log); err != nil {
			log.Error("work failed", "err", err)
			os.Exit(1)
		}
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
	// means a read-path-only deployment (write endpoints answer 503). A PARTIAL R2
	// config fails fast here rather than accepting traffic and erroring per request
	// (review ruling 7).
	sc, err := service.LoadStorage(ctx)
	if err != nil {
		return err
	}
	if sc.Storage != nil {
		log.Info("write path enabled (storage configured)")
	} else {
		log.Info("read-path-only (no storage configured; write endpoints return 503)")
	}

	svc := service.New(service.Config{
		Store:              st,
		Verifier:           cfg.Verifier,
		URLs:               cfg.URLs,
		Storage:            sc.Storage,
		Prober:             sc.Prober,
		UploadTTL:          sc.UploadTTL,
		UploadMaxBytes:     sc.UploadMaxBytes,
		DeliverySigningKey: cfg.DeliverySigningKey,
		ImgproxyKey:        cfg.ImgproxyKey,
		ImgproxySalt:       cfg.ImgproxySalt,
		GrantURLTTL:        cfg.GrantURLTTL,
		GrantCacheTTL:      cfg.GrantCacheTTL,
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

// work runs the transcode worker (spec §5.2, Q4). Unlike serve, storage is
// REQUIRED — the worker's whole job is pulling originals and writing renditions.
func work(log *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := service.LoadEnv()
	if err != nil {
		return err
	}
	sc, err := service.LoadStorage(ctx)
	if err != nil {
		return err
	}
	if sc.Storage == nil {
		return fmt.Errorf("plate work: storage is required (set R2_ENDPOINT / R2_DEFAULT_BUCKET)")
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	w := worker.New(worker.Config{
		Store:              st,
		Storage:            sc.Storage,
		Transcoder:         worker.NewFFmpegTranscoder(os.Getenv("PLATE_FFMPEG_PATH"), "", 0),
		Prober:             sc.Prober,
		Log:                log,
		ScratchDir:         os.Getenv("PLATE_WORKER_SCRATCH_DIR"),
		DetailMaxDurationS: service.DetailMaxDurationSeconds(), // PLATE_DETAIL_MAX_DURATION, default 720
	})

	// The reconciliation sweeps (orphaned uploads + two-step deleted-asset purge,
	// spec §5.1/§Q2) run on a ticker inside the worker — the scheduler they were
	// built for but never had. Kept in-process (not a separate Fly cron machine):
	// the worker already holds the store + storage, and the sweeps are periodic
	// housekeeping. Interval + grace are env-tunable; defaults are safe.
	reconciler := worker.NewReconciler(st, sc.Storage, log,
		parseDurationEnv("PLATE_SWEEP_GRACE", 0),     // 0 → 6h default
		0,                                            // batch size default (100)
	)
	go reconciler.SweepLoop(ctx, parseDurationEnv("PLATE_SWEEP_EVERY", 15*time.Minute))

	// Graceful SIGTERM: cancel the loop's context so an in-flight job finishes or
	// releases its lease, then exit (K8s-ready, spec Q4). This also stops SweepLoop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Info("worker: signal received, stopping")
		cancel()
	}()

	log.Info("plate work")
	if err := w.Run(ctx); err != nil && err != context.Canceled {
		return err
	}
	return nil
}

// parseDurationEnv reads a Go duration from an env var, falling back to def on
// absent/invalid. Small local helper so the worker's tunables read from one place.
func parseDurationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

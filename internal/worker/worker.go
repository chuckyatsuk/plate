package worker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/probe"
	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
)

// Worker is the `plate work` run-loop (spec §5.2, Q4). It claims queued A/V jobs
// (Postgres SKIP LOCKED), pulls the vault original from storage, transcodes with
// ffmpeg, writes the rendition back, and records durable state — the job and its
// rendition committing together so a crash never leaves a "succeeded but no
// record" split. It is idempotent and retryable: because the vault write already
// succeeded, a failed derivative is recoverable, never data loss.
type Worker struct {
	store      *store.Postgres
	storage    storage.Storage
	transcoder Transcoder
	prober     *probe.Prober
	log        *slog.Logger

	scratchDir  string
	leaseTTL    time.Duration
	pollEvery   time.Duration
	maxAttempts int32
}

// Config wires the worker. Values come from the environment in production
// (twelve-factor, spec Q4).
type Config struct {
	Store      *store.Postgres
	Storage    storage.Storage
	Transcoder Transcoder
	Prober     *probe.Prober
	Log        *slog.Logger

	ScratchDir  string        // real disk for ffmpeg, NOT tmpfs (spec Q4)
	LeaseTTL    time.Duration // a running job with an older heartbeat is reclaimable
	PollEvery   time.Duration // how often to poll an empty queue
	MaxAttempts int32         // retries before a job is marked failed
}

// New builds a Worker with sane defaults for the zero values.
func New(cfg Config) *Worker {
	w := &Worker{
		store:       cfg.Store,
		storage:     cfg.Storage,
		transcoder:  cfg.Transcoder,
		prober:      cfg.Prober,
		log:         cfg.Log,
		scratchDir:  cfg.ScratchDir,
		leaseTTL:    cfg.LeaseTTL,
		pollEvery:   cfg.PollEvery,
		maxAttempts: cfg.MaxAttempts,
	}
	if w.log == nil {
		w.log = slog.Default()
	}
	if w.scratchDir == "" {
		w.scratchDir = os.TempDir()
	}
	if w.leaseTTL <= 0 {
		w.leaseTTL = 15 * time.Minute
	}
	if w.pollEvery <= 0 {
		w.pollEvery = 2 * time.Second
	}
	if w.maxAttempts <= 0 {
		w.maxAttempts = 3
	}
	return w
}

// Run loops until ctx is cancelled (graceful SIGTERM shutdown, spec Q4). It
// claims and runs one job at a time; when the queue is empty it sleeps pollEvery.
// A single worker is intentionally simple — horizontal scale is "run N workers",
// and SKIP LOCKED makes them safe together.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("worker started", "lease_ttl", w.leaseTTL, "poll_every", w.pollEvery)
	for {
		select {
		case <-ctx.Done():
			w.log.Info("worker shutting down")
			return ctx.Err()
		default:
		}

		claimed, err := w.store.ClaimNextJob(ctx, w.leaseTTL)
		if err == store.ErrNoJob {
			if !sleep(ctx, w.pollEvery) {
				return ctx.Err()
			}
			continue
		}
		if err != nil {
			w.log.Error("claim job failed", "err", err)
			if !sleep(ctx, w.pollEvery) {
				return ctx.Err()
			}
			continue
		}

		w.runOne(ctx, claimed)
	}
}

// runOne executes a single claimed job end to end, recording success or failure.
// It never propagates the error up (a failed job is recorded, not fatal to the
// loop) — the whole point is that the worker survives a bad job.
func (w *Worker) runOne(ctx context.Context, job store.ClaimedJob) {
	log := w.log.With("job", job.ID, "asset", job.Asset, "intent", string(job.Intent), "attempt", job.Attempts)
	log.Info("job claimed")

	if err := w.process(ctx, job); err != nil {
		reason := plate.ReasonCodeFailed
		log.Error("job failed", "err", err)
		if ferr := w.store.FailJob(ctx, job.ID, w.maxAttempts, reason, err.Error()); ferr != nil {
			log.Error("recording job failure failed", "err", ferr)
		}
		return
	}
	log.Info("job succeeded")
}

// process does the work: pull → transcode → probe → put → complete. It is
// idempotent — the rendition key is deterministic, so a re-run overwrites rather
// than duplicates.
func (w *Worker) process(ctx context.Context, job store.ClaimedJob) error {
	// Scratch files for this job (spec Q4: real scratch disk).
	work, err := os.MkdirTemp(w.scratchDir, "plate-job-"+job.ID+"-*")
	if err != nil {
		return fmt.Errorf("scratch dir: %w", err)
	}
	defer os.RemoveAll(work)

	srcPath := filepath.Join(work, "source")
	dstPath := filepath.Join(work, "rendition"+outputExt(job.Intent))

	// Pull the vault original from storage (server-to-server; the worker holds the
	// derivative-path credentials, spec §5.1).
	if err := w.download(ctx, job.VaultKey, srcPath); err != nil {
		return fmt.Errorf("pull vault original: %w", err)
	}

	// Heartbeat while the transcode runs so a long job's lease is not reclaimed.
	beat, stopBeat := context.WithCancel(ctx)
	defer stopBeat()
	go w.heartbeatLoop(beat, job.ID)

	if err := w.transcoder.Transcode(ctx, job.Intent, srcPath, dstPath); err != nil {
		return err
	}
	stopBeat()

	// Probe the produced rendition for its true dimensions/duration.
	rend, err := w.probeRendition(ctx, job, dstPath)
	if err != nil {
		return fmt.Errorf("probe rendition: %w", err)
	}

	// Write the rendition to its deterministic key and record it + complete the
	// job in one transaction.
	rendKey := renditionKey(job.VaultKey, job.Intent)
	if err := w.upload(ctx, dstPath, rendKey, contentType(job.Intent)); err != nil {
		return fmt.Errorf("put rendition: %w", err)
	}
	rend.Key = rendKey
	rend.Mode = string(plate.Public)

	return w.store.CompleteJob(ctx, job.ID, rend)
}

func (w *Worker) heartbeatLoop(ctx context.Context, jobID string) {
	t := time.NewTicker(w.leaseTTL / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.store.Heartbeat(ctx, jobID, 0.5); err != nil {
				w.log.Warn("heartbeat failed", "job", jobID, "err", err)
			}
		}
	}
}

func (w *Worker) probeRendition(ctx context.Context, job store.ClaimedJob, path string) (store.RenditionRecord, error) {
	var rec store.RenditionRecord
	if job.Intent == plate.Poster {
		pr, err := w.prober.ProbeImage(path)
		if err != nil {
			return rec, err
		}
		rec.Width, rec.Height = ptrInt32(pr.Width), ptrInt32(pr.Height)
		return rec, nil
	}
	pr, err := w.prober.ProbeAV(ctx, path)
	if err != nil {
		return rec, err
	}
	rec.Width, rec.Height = ptrInt32(pr.Width), ptrInt32(pr.Height)
	if pr.DurationS > 0 {
		d := pr.DurationS
		rec.DurationS = &d
	}
	// detail carries audio; loop is silent (spec §5.4).
	hasAudio := job.Intent == plate.Detail
	rec.HasAudio = &hasAudio
	return rec, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (w *Worker) download(ctx context.Context, key, dst string) error {
	body, err := w.storage.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, body)
	return err
}

func (w *Worker) upload(ctx context.Context, src, key, ctype string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return w.storage.Put(ctx, key, ctype, f, fi.Size())
}

// renditionKey is the deterministic object key for a rendition:
// {vault-key}/{intent}. Deterministic so a re-run overwrites (idempotent).
func renditionKey(vaultKey string, intent plate.Intent) string {
	return vaultKey + "/" + string(intent)
}

func outputExt(intent plate.Intent) string {
	switch intent {
	case plate.Poster:
		return ".jpg"
	default:
		return ".mp4"
	}
}

func contentType(intent plate.Intent) string {
	switch intent {
	case plate.Poster:
		return "image/jpeg"
	default:
		return "video/mp4"
	}
}

func ptrInt32(n int) *int32 {
	if n <= 0 {
		return nil
	}
	v := int32(n)
	return &v
}

// sleep waits d or returns false if ctx is cancelled first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

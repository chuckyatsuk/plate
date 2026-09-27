package worker

// The checksum sweep (Exit support, P3): Plate computes the SHA-256 of every
// vault object itself and records it as the verified vault checksum, so an
// owner's export can be verified against a digest Plate vouches for.
//
// Where the bytes are read:
//   - A/V originals: the derive job already downloads them (downloadHashed), so
//     it hashes them then; the sweep leaves an asset with a queued or running
//     derive job alone.
//   - Everything else — images, documents, skip_derivations A/V, and every
//     asset that predates this — is hashed here, on the WORKER, never in the
//     API's finalize: a 2 GB document hashed inside a request on a 512 MB API
//     machine is exactly the "multi-GB object through a request" failure the
//     broker exists to avoid. The object is streamed through the hash (a 32 KiB
//     copy buffer), never buffered, and rate-limited so a backfill cannot
//     saturate the worker's link while it transcodes.
//
// The same Checksummer drives the worker's periodic loop and the operator's
// `plate checksums run` backfill, so there is one implementation of "hash an
// object and record it", not two.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
)

// ChecksumStore is what the checksummer needs from the store.
type ChecksumStore interface {
	ClaimChecksumCandidate(ctx context.Context, retryBefore time.Time) (store.ChecksumCandidate, error)
	MarkChecksumVerified(ctx context.Context, assetID, checksum string) error
	ReleaseChecksumClaim(ctx context.Context, assetID string) error
}

var _ ChecksumStore = (*store.Postgres)(nil)

// Checksummer hashes vault objects that lack a verified SHA-256.
type Checksummer struct {
	store   ChecksumStore
	storage storage.Storage
	log     *slog.Logger

	rate       int64         // bytes per second through the hash; <= 0 is unthrottled
	retryAfter time.Duration // a failed object is not retried sooner than this
	perObject  time.Duration // one object's read must finish within this
}

// ChecksumConfig configures a Checksummer. Zero values take the defaults.
type ChecksumConfig struct {
	// RateBytesPerSec caps read throughput (default 16 MiB/s; negative = no cap).
	RateBytesPerSec int64
	// RetryAfter is the back-off before an object that failed is tried again
	// (default 6h).
	RetryAfter time.Duration
	// PerObjectTimeout bounds one object's read (default 1h: a 2 GB original at
	// the default rate is ~2 minutes, so this only stops a hung read).
	PerObjectTimeout time.Duration
}

// DefaultChecksumRate is the default throughput cap: gentle beside a running
// transcode, yet ~1 GB a minute.
const DefaultChecksumRate = 16 << 20

// NewChecksummer builds a Checksummer.
func NewChecksummer(st ChecksumStore, stor storage.Storage, log *slog.Logger, cfg ChecksumConfig) *Checksummer {
	if log == nil {
		log = slog.Default()
	}
	c := &Checksummer{store: st, storage: stor, log: log,
		rate: cfg.RateBytesPerSec, retryAfter: cfg.RetryAfter, perObject: cfg.PerObjectTimeout}
	if c.rate == 0 {
		c.rate = DefaultChecksumRate
	}
	if c.retryAfter <= 0 {
		c.retryAfter = 6 * time.Hour
	}
	if c.perObject <= 0 {
		c.perObject = time.Hour
	}
	return c
}

// PassResult counts one pass's work.
type PassResult struct {
	Hashed     int   // objects hashed and recorded verified
	Failed     int   // objects that could not be read in full (retried after the back-off)
	Mismatched int   // objects whose sha256 differs from an already-verified one (kept, logged)
	Bytes      int64 // bytes read through the hash
}

// RunPass claims and hashes pending objects one at a time until none remain,
// max objects have been claimed (max <= 0: no limit), or ctx ends. Resumable by
// construction: progress is the column itself, so a pass stopped anywhere loses
// at most the object in flight, which the next pass retries after the back-off.
func (c *Checksummer) RunPass(ctx context.Context, max int) (PassResult, error) {
	var res PassResult
	for claimed := 0; max <= 0 || claimed < max; claimed++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		cand, err := c.store.ClaimChecksumCandidate(ctx, time.Now().Add(-c.retryAfter))
		if errors.Is(err, store.ErrNoChecksumPending) {
			return res, nil
		}
		if err != nil {
			return res, err
		}
		sum, n, err := c.hash(ctx, cand.VaultKey)
		res.Bytes += n
		if err == nil && n != cand.SizeBytes {
			err = fmt.Errorf("read %d bytes, the vault records %d", n, cand.SizeBytes)
		}
		if err != nil {
			if ctx.Err() != nil {
				// Interrupted (shutdown, Ctrl-C), not a bad object: hand the claim
				// back so the next pass takes it at once instead of after the
				// failure back-off.
				rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if rerr := c.store.ReleaseChecksumClaim(rctx, cand.ID); rerr != nil {
					c.log.Warn("checksum: releasing interrupted claim failed", "asset", cand.ID, "err", rerr)
				}
				cancel()
				return res, ctx.Err()
			}
			res.Failed++
			c.log.Warn("checksum: could not hash vault object; will retry after back-off",
				"asset", cand.ID, "account", cand.Account, "key", cand.VaultKey, "retry_after", c.retryAfter, "err", err)
			continue
		}
		switch err := c.store.MarkChecksumVerified(ctx, cand.ID, sum); {
		case errors.Is(err, store.ErrChecksumMismatch):
			res.Mismatched++
			c.log.Error("checksum: vault object no longer matches its verified sha256",
				"asset", cand.ID, "account", cand.Account, "computed", sum)
		case err != nil:
			return res, err
		default:
			res.Hashed++
		}
	}
	return res, nil
}

// Loop runs a pass every `every` until ctx ends — the worker's standing sweep.
// Each pass drains whatever is pending (at the rate cap), so newly finalized
// images and documents are hashed within about one interval, and a backlog
// (the first deploy's backfill) drains in the first passes. Errors are logged
// and retried next tick; the loop never takes the worker down.
func (c *Checksummer) Loop(ctx context.Context, every time.Duration) {
	c.log.Info("checksum: sweep loop started", "every", every, "rate_bytes_per_sec", c.rate)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		res, err := c.RunPass(ctx, 0)
		if err != nil && ctx.Err() == nil {
			c.log.Warn("checksum: sweep pass failed", "err", err)
		}
		if res.Hashed+res.Failed+res.Mismatched > 0 {
			c.log.Info("checksum: sweep pass done", "hashed", res.Hashed, "failed", res.Failed,
				"mismatched", res.Mismatched, "bytes", res.Bytes)
		}
		select {
		case <-ctx.Done():
			c.log.Info("checksum: sweep loop stopping")
			return
		case <-t.C:
		}
	}
}

// hash streams one object through SHA-256 at the rate cap.
func (c *Checksummer) hash(ctx context.Context, key string) (string, int64, error) {
	octx, cancel := context.WithTimeout(ctx, c.perObject)
	defer cancel()
	body, err := c.storage.Get(octx, key)
	if err != nil {
		return "", 0, err
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(h, &throttledReader{ctx: octx, r: body, rate: c.rate, start: time.Now()})
	if err != nil {
		return "", n, err
	}
	return store.ChecksumPrefix + hex.EncodeToString(h.Sum(nil)), n, nil
}

// recordChecksum records a SHA-256 computed while a derive job downloaded the
// vault original. Only a complete read is recorded (n must equal the vault's
// recorded size); anything else, and a mismatch with an already-verified sha256,
// is logged and left for the sweep. Never fails the job: the rendition is the
// job's work, the checksum is a by-product of its read.
func recordChecksum(ctx context.Context, st ChecksumStore, log *slog.Logger, assetID, sum string, n, size int64) {
	if n != size {
		log.Warn("checksum: derive download size differs from the vault record; not recorded",
			"asset", assetID, "read", n, "recorded", size)
		return
	}
	switch err := st.MarkChecksumVerified(ctx, assetID, sum); {
	case errors.Is(err, store.ErrChecksumMismatch):
		log.Error("checksum: vault object no longer matches its verified sha256", "asset", assetID, "computed", sum)
	case err != nil:
		log.Warn("checksum: recording derive-time sha256 failed; the sweep will hash it", "asset", assetID, "err", err)
	}
}

// throttledReader caps average read throughput at rate bytes/second by sleeping
// whenever it runs ahead of schedule. rate <= 0 passes reads straight through.
type throttledReader struct {
	ctx   context.Context
	r     io.Reader
	rate  int64
	start time.Time
	n     int64
}

func (t *throttledReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.n += int64(n)
	if t.rate > 0 && n > 0 {
		due := time.Duration(float64(t.n) / float64(t.rate) * float64(time.Second))
		if ahead := due - time.Since(t.start); ahead > 0 {
			timer := time.NewTimer(ahead)
			select {
			case <-t.ctx.Done():
				timer.Stop()
				return n, t.ctx.Err()
			case <-timer.C:
			}
		}
	}
	return n, err
}

package plate_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/chuckyatsuk/plate/internal/worker"
)

// runChecksumSweep runs one unthrottled pass of the worker's checksum sweep
// (the same Checksummer `plate work` and `plate checksums run` drive) and
// returns how many objects it hashed. Kept in its own file so the sweep tests
// can be run against the pre-batch code with a no-op stand-in (there was no
// sweep), which is how they were proven to fail there.
func (e *e2e) runChecksumSweep(t *testing.T) int {
	t.Helper()
	cs := worker.NewChecksummer(e.st, e.stor.Storage, slog.Default(), worker.ChecksumConfig{RateBytesPerSec: -1})
	res, err := cs.RunPass(context.Background(), 0)
	if err != nil {
		t.Fatalf("checksum sweep: %v", err)
	}
	return res.Hashed
}

// newTestChecksummer is an unthrottled Checksummer over the e2e store/storage.
func newTestChecksummer(e *e2e) *worker.Checksummer {
	return worker.NewChecksummer(e.st, e.stor.Storage, slog.Default(), worker.ChecksumConfig{RateBytesPerSec: -1})
}

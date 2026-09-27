package worker

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/store"
)

// The rate cap is real: reading N bytes at R bytes/s takes about N/R.
func TestThrottledReader_CapsThroughput(t *testing.T) {
	const size, rate = 64 << 10, 256 << 10 // 64 KiB at 256 KiB/s ≈ 250ms
	tr := &throttledReader{ctx: context.Background(), r: bytes.NewReader(make([]byte, size)), rate: rate, start: time.Now()}
	start := time.Now()
	n, err := io.Copy(io.Discard, tr)
	if err != nil || n != size {
		t.Fatalf("copy = %d, %v", n, err)
	}
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Fatalf("read %d bytes at %d B/s in %s; the cap is not applied", size, rate, el)
	}
}

func TestThrottledReader_UnthrottledAndCancel(t *testing.T) {
	tr := &throttledReader{ctx: context.Background(), r: bytes.NewReader(make([]byte, 1<<20)), rate: -1, start: time.Now()}
	start := time.Now()
	if n, _ := io.Copy(io.Discard, tr); n != 1<<20 || time.Since(start) > time.Second {
		t.Fatalf("unthrottled read slowed: %d bytes in %s", n, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr = &throttledReader{ctx: ctx, r: bytes.NewReader(make([]byte, 1<<20)), rate: 1, start: time.Now()}
	if _, err := io.Copy(io.Discard, tr); err == nil {
		t.Fatal("a cancelled context must stop a throttled read")
	}
}

type recStore struct{ marked []string }

func (r *recStore) ClaimChecksumCandidate(context.Context, time.Time) (store.ChecksumCandidate, error) {
	return store.ChecksumCandidate{}, store.ErrNoChecksumPending
}
func (r *recStore) MarkChecksumVerified(_ context.Context, id, sum string) error {
	r.marked = append(r.marked, id+"="+sum)
	return nil
}
func (r *recStore) ReleaseChecksumClaim(context.Context, string) error { return nil }

// A derive download that read a different byte count than the vault records is
// never recorded as the object's checksum.
func TestRecordChecksum_OnlyACompleteRead(t *testing.T) {
	st := &recStore{}
	recordChecksum(context.Background(), st, slog.Default(), "a1", "sha256:x", 99, 100)
	if len(st.marked) != 0 {
		t.Fatalf("a short read was recorded: %v", st.marked)
	}
	recordChecksum(context.Background(), st, slog.Default(), "a1", "sha256:x", 100, 100)
	if len(st.marked) != 1 {
		t.Fatalf("a complete read was not recorded: %v", st.marked)
	}
}

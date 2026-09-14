package plate_test

// The worker heartbeat loop (Tier 1 monitoring): proves the worker's ONLY
// liveness signal actually lands in worker_heartbeats on the interval, carries
// the reconciler's last-sweep time once one exists, and stops with its context.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/worker"
)

func TestWorkerHeartbeatLoop_BeatsAndCarriesSweep(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var sweepAt *time.Time
	lastSweep := func() *time.Time { return sweepAt }

	done := make(chan struct{})
	go func() {
		worker.HeartbeatLoop(ctx, st, slog.Default(), "test-machine", "img:test", 100*time.Millisecond, lastSweep)
		close(done)
	}()

	// First beat is immediate.
	deadline := time.Now().Add(3 * time.Second)
	for {
		wl, err := st.WorkerLiveness(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if wl.Seen && wl.WorkerID == "test-machine" && wl.Version == "img:test" {
			if wl.LastSweep != nil {
				t.Fatalf("no sweep has run; last_sweep should be nil, got %v", *wl.LastSweep)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no heartbeat row within 3s: %+v", wl)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// A sweep completes → the next beat carries it.
	now := time.Now().Truncate(time.Millisecond)
	sweepAt = &now
	deadline = time.Now().Add(3 * time.Second)
	for {
		wl, _ := st.WorkerLiveness(ctx)
		if wl.LastSweep != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("last_sweep never propagated through the heartbeat")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Stops with its context.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat loop did not stop on context cancel")
	}
}

package plate_test

// Requirement (spec §5.1, accepted cost of brokered uploads): "a browser that
// PUTs successfully then closes the tab leaves an orphan object with no asset
// record. Requires a reconciliation sweep (list bucket, find keys with no asset,
// clean up after N hours)."
//
// The sweep itself is PR-(b) (it lands with the worker). But a table that records
// pending uploads with NO proof it is ever swept is exactly how that accepted
// cost quietly becomes a permanent leak (decision D5). So this test HOLDS the
// requirement now: it proves an unfinalized upload older than the grace window is
// RECLAIMABLE (surfaced by store.ReclaimableUploads), and a finalized one is NOT.
// When the sweep is written, it consumes exactly this query.
//
// It runs against the same ephemeral Postgres the isolation suite uses (spec §7,
// Q2) — no live DB.

import (
	"context"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/store"
)

func TestUnfinalizedUpload_IsReclaimable(t *testing.T) {
	st := storeForTest(t) // ephemeral Postgres, migrated + a seeded account
	ctx := context.Background()

	// An upload the browser created but never finalized (the tab-closed orphan).
	orphan := store.Upload{
		ID:          "01RECONCILEORPHAN000000001",
		Account:     reconcileAccount,
		Key:         reconcileAccount + "/01RECONCILEORPHAN000000001",
		ContentType: "image/jpeg",
		SizeBytes:   1234,
	}
	if err := st.CreateUpload(ctx, reconcileAccount, orphan); err != nil {
		t.Fatalf("create orphan upload: %v", err)
	}

	// A second upload that WAS finalized — must NOT be reclaimable.
	finalized := store.Upload{
		ID:          "01RECONCILEDONE00000000001",
		Account:     reconcileAccount,
		Key:         reconcileAccount + "/01RECONCILEDONE00000000001",
		ContentType: "image/jpeg",
		SizeBytes:   1234,
	}
	if err := st.CreateUpload(ctx, reconcileAccount, finalized); err != nil {
		t.Fatalf("create finalized upload: %v", err)
	}
	// Finalize it (records an asset + marks finalized_at). Minimal vault record.
	if _, err := st.FinalizeUpload(ctx, reconcileAccount, finalized.ID, store.VaultRecord{
		Kind: "image", Checksum: "sha256:done", SizeBytes: 1234,
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// Sweep for uploads older than "now" (both are older than a moment from now):
	// only the orphan should appear.
	reclaimable, err := st.ReclaimableUploads(ctx, time.Now().Add(time.Second), 100)
	if err != nil {
		t.Fatalf("reclaimable query: %v", err)
	}

	var sawOrphan, sawFinalized bool
	for _, u := range reclaimable {
		switch u.ID {
		case orphan.ID:
			sawOrphan = true
		case finalized.ID:
			sawFinalized = true
		}
	}
	if !sawOrphan {
		t.Fatalf("the unfinalized upload %q was NOT reclaimable — the orphan-reconciliation requirement (spec §5.1) is not held; a tab-closed upload would leak forever", orphan.ID)
	}
	if sawFinalized {
		t.Fatalf("a FINALIZED upload %q was reported reclaimable — the sweep would delete a live asset's object", finalized.ID)
	}
}

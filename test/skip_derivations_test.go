package plate_test

// skip_derivations — the opt-out of the automatic derivation at ingest, and the
// `not_derived` terminal state it produces (Tier 2 V2).
//
// The rule being tested has two halves, and BOTH matter:
//
//  1. TERMINAL FOR THE AUTOMATIC PATH. finalize with the flag enqueues no job
//     and records EVERY derivable intent for the kind as `not_derived`, so each
//     one answers honestly at delivery: `delivery: null` + reason `not_derived`.
//     The negative assertion is the point — reason must NOT be `pending`, which
//     would tell a caller to poll forever for a rendition nothing will produce.
//     That lie is easy to reintroduce: the resolver's status switch has a
//     `default` arm answering `pending`, so a missing `case` is a silent wrong
//     answer rather than a compile error.
//
//  2. REQUESTABLE ON DEMAND. The flag declines the AUTOMATIC enqueue; it is not
//     a ban on ever deriving. An archive-only asset the owner later wants shown
//     is an ordinary change of mind, so an explicit rendition request treats a
//     `not_derived` row as if no row existed: it enqueues, and the job's result
//     replaces the row (ending `ready`).
//
// Drives the real service + MinIO through the same e2e harness as the other
// upload tests; the A/V fixture needs ffmpeg (harness.RequireFFmpeg).

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/harness"
)

// uploadAndFinalizeSkippingDerivations is uploadAndFinalize with
// skip_derivations set on the createUpload call.
func (e *e2e) uploadAndFinalizeSkippingDerivations(path, contentType string) string {
	e.t.Helper()
	return e.uploadAndFinalizeOpts(path, contentType, "md5:unverified-in-test", true)
}

// finalizeResponseSkippingDerivations returns the FINALIZE RESPONSE BODY itself,
// not just the asset id — so a test can assert what that response claimed at the
// moment it was sent, which is what a client actually reads.
func (e *e2e) finalizeResponseSkippingDerivations(path, contentType string) plate.Asset {
	e.t.Helper()
	assetID := e.uploadAndFinalizeOpts(path, contentType, "md5:unverified-in-test", true)
	// uploadAndFinalizeOpts asserts the 201 and keeps the body; re-read it from
	// the recorded response the helper stashed.
	var a plate.Asset
	mustDecode(e.t, e.lastFinalizeBody, &a)
	if string(a.Id) != assetID {
		e.t.Fatalf("finalize body asset id %q != %q", a.Id, assetID)
	}
	return a
}

func TestSkipDerivations_MarksEveryDerivableIntentNotDerived(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	// A short, well-under-ceiling video: nothing about this asset would refuse
	// on its own merits, so a `not_derived` answer can only come from the flag.
	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "archive.mp4"), 3*time.Second, true)
	assetID := e.uploadAndFinalizeSkippingDerivations(src, "video/mp4")

	// NO job was enqueued: draining the worker is a no-op. If finalize had
	// enqueued `detail` despite the flag, the drain would produce a rendition
	// and the assertions below would fail.
	e.drainWorker()

	// Every derivable video intent is recorded, not just the auto-enqueued one.
	// poster/loop left absent would resolve as `pending` — the same lie in a
	// different place, which is why the contract marks all three.
	for _, intent := range []string{"poster", "loop", "detail"} {
		res := e.resolve(assetID, intent)
		if res.Delivery != nil {
			t.Fatalf("intent %s: expected no delivery for a skip_derivations asset, got one", intent)
		}
		if res.Reason == nil {
			t.Fatalf("intent %s: expected a refusal reason, got none", intent)
		}
		if *res.Reason == string(plate.ReasonCodePending) {
			t.Fatalf("intent %s: reason is `pending` — a caller would poll forever for a "+
				"rendition no automatic path will ever produce. The resolver is missing its "+
				"`not_derived` case and fell through to the default arm.", intent)
		}
		if *res.Reason != string(plate.ReasonCodeNotDerived) {
			t.Fatalf("intent %s: reason = %q, want %q", intent, *res.Reason, plate.ReasonCodeNotDerived)
		}
	}
}

func TestSkipDerivations_ExplicitRequestOverridesNotDerived(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "archive2.mp4"), 3*time.Second, true)
	assetID := e.uploadAndFinalizeSkippingDerivations(src, "video/mp4")

	// Precondition: detail is not-derived to begin with.
	if res := e.resolve(assetID, "detail"); res.Reason == nil || *res.Reason != string(plate.ReasonCodeNotDerived) {
		t.Fatalf("precondition: detail should start not_derived, got %+v", res.Reason)
	}

	// The owner changes their mind. This request is a NEW decision, so the
	// endpoint must treat the not_derived row as if no row existed and ENQUEUE —
	// a 202 with a job, not a 200 echoing the not_derived row back.
	resp := e.req("POST", "/v1/assets/"+assetID+"/renditions", mustJSON(map[string]any{"intent": "detail"}))
	if resp.Code != 202 {
		t.Fatalf("expected 202 (job enqueued) for an explicit request over a not_derived row, "+
			"got HTTP %d: %s — the idempotency short-circuit is still swallowing it", resp.Code, resp.Body.String())
	}

	// The job runs and its result REPLACES the row.
	e.drainWorker()

	res := e.resolve(assetID, "detail")
	if res.Delivery == nil {
		t.Fatalf("after an explicit request + worker run, detail should deliver; got reason %v", res.Reason)
	}
}

func TestSkipDerivations_OmittedIsUnchangedBehavior(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	// The additive half of the contract change: a caller that never sends the
	// flag must be indistinguishable from before it existed — finalize still
	// auto-enqueues detail, and nothing is marked not_derived.
	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "normal.mp4"), 3*time.Second, true)
	assetID := e.uploadAndFinalize(src, "video/mp4")
	e.drainWorker()

	res := e.resolve(assetID, "detail")
	if res.Delivery == nil {
		t.Fatalf("a normal upload must still auto-derive detail; got reason %v", res.Reason)
	}
}

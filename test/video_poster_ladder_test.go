package plate_test

// A VIDEO's image intents serve its POSTER, bounded (V2.1).
//
// WHY this exists: Plate's derived `poster` is ONE FULL-RESOLUTION keyframe
// served as a plain public file. Handing that to a grid tile is the unbounded
// decode the whole memory budget exists to prevent — a 4K poster is the same
// class of failure as the 292MB-RGBA incident. So a still of a video must come
// through the same bounded imgproxy ladder an image's vault original gets, and
// that bounding belongs HERE, once, not in every consumer that shows a video.
//
// Three properties, each of which has a way of silently breaking:
//   1. thumbnail/grid/lightbox on a video deliver a BOUNDED url (not raw bytes),
//      sourced from the poster RENDITION rather than the video's vault key.
//   2. The dimensions reported are the POSTER's, not the video's.
//   3. If the poster is not ready, the image intent INHERITS its state — a
//      not_derived poster answers not_derived, never `pending`. This is the lie
//      the tier removed, and it would reappear the moment a consumer polls a
//      thumbnail that will never arrive.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestVideoImageIntent_ServesBoundedPoster(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "poster-ladder.mp4"), 3*time.Second, true)
	assetID := e.uploadAndFinalize(src, "video/mp4")
	// finalize auto-enqueues detail; ask for the poster too, then let the worker
	// produce both.
	if resp := e.req("POST", "/v1/assets/"+assetID+"/renditions", mustJSON(map[string]any{"intent": "poster"})); resp.Code != 202 {
		t.Fatalf("request poster: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	e.drainWorker()

	for _, intent := range []string{"thumbnail", "grid", "lightbox"} {
		res := e.resolve(assetID, intent)
		if res.Delivery == nil {
			t.Fatalf("intent %s on a video with a ready poster refused (reason %v) — it should serve the bounded poster", intent, res.Reason)
		}
		u := res.Delivery.URL
		// The bounded ladder means an imgproxy URL, not the raw public object.
		// A raw `delivery/.../poster` URL here is the unbounded-decode bug.
		if strings.Contains(u, "/delivery/") && !strings.Contains(u, "/plain/") {
			t.Fatalf("intent %s returned what looks like the RAW poster object (%s) — it must be transformed through the image engine, or a 4K keyframe reaches the grid tile unbounded", intent, u)
		}
		// Dimensions must be reported, and must come from the poster (160x120
		// here), not be absent because the code read the video's vault dims.
		if res.Delivery.Width == nil || res.Delivery.Height == nil {
			t.Fatalf("intent %s: no output dimensions — a consumer cannot build a srcset without them", intent)
		}
		if *res.Delivery.Width > 160 || *res.Delivery.Height > 120 {
			t.Fatalf("intent %s: reported %dx%d, larger than the 160x120 poster — dims are not coming from the poster rendition",
				intent, *res.Delivery.Width, *res.Delivery.Height)
		}
	}
}

// The state-inheritance property: a video whose poster will NEVER exist must say
// so on its image intents too. Built with skip_derivations, which marks poster
// not_derived, so thumbnail must answer not_derived rather than pending.
func TestVideoImageIntent_InheritsNotDerivedPosterState(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "no-poster.mp4"), 3*time.Second, true)
	assetID := e.uploadAndFinalizeSkippingDerivations(src, "video/mp4")
	e.drainWorker()

	for _, intent := range []string{"thumbnail", "grid", "lightbox"} {
		res := e.resolve(assetID, intent)
		if res.Delivery != nil {
			t.Fatalf("intent %s delivered a URL for a video whose poster is not_derived", intent)
		}
		if res.Reason == nil {
			t.Fatalf("intent %s: no reason given", intent)
		}
		if *res.Reason == string(plate.ReasonCodePending) {
			t.Fatalf("intent %s answered `pending` for a poster that will NEVER be derived — a consumer would poll forever. It must inherit the poster's not_derived state.", intent)
		}
		if *res.Reason != string(plate.ReasonCodeNotDerived) {
			t.Fatalf("intent %s: reason = %q, want %q", intent, *res.Reason, plate.ReasonCodeNotDerived)
		}
	}
}

// Deleted means not served (V2.1): once deleted_at is set, delivery refuses on
// every intent. The two-step delete is about reclaiming BYTES later, not about
// continuing to serve in the meantime.
func TestDeletedAsset_RefusesDelivery(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "doomed.mp4"), 3*time.Second, true)
	assetID := e.uploadAndFinalize(src, "video/mp4")
	e.drainWorker()

	// Precondition: it serves before the delete.
	if res := e.resolve(assetID, "detail"); res.Delivery == nil {
		t.Fatalf("precondition: detail should deliver before deletion; reason %v", res.Reason)
	}

	if resp := e.req("DELETE", "/v1/assets/"+assetID, nil); resp.Code != 202 && resp.Code != 200 {
		t.Fatalf("delete: HTTP %d: %s", resp.Code, resp.Body.String())
	}

	for _, intent := range []string{"detail", "thumbnail"} {
		res := e.resolve(assetID, intent)
		if res.Delivery != nil {
			t.Fatalf("intent %s still delivered %s AFTER the asset was deleted — marked deleted means not served", intent, res.Delivery.URL)
		}
		if res.Reason == nil || *res.Reason != string(plate.ReasonCodeDeleted) {
			got := "<nil>"
			if res.Reason != nil {
				got = *res.Reason
			}
			t.Fatalf("intent %s: reason = %q, want %q", intent, got, plate.ReasonCodeDeleted)
		}
	}
}

// The finalize RESPONSE must reflect stored state (V2.1). It used to be built
// before the not_derived marks were written, so it reported `renditions: []` for
// an asset that already had three not_derived rows — a lie a client could act
// on, and exactly what V3's ingest would have read.
func TestFinalizeResponse_ReflectsStoredNotDerivedRows(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)

	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "finalize-honesty.mp4"), 3*time.Second, true)
	asset := e.finalizeResponseSkippingDerivations(src, "video/mp4")

	if len(asset.Renditions) == 0 {
		t.Fatal("finalize returned `renditions: []` for a skip_derivations upload whose rows were already written — the response must reflect stored state, not a snapshot taken before the marks")
	}
	got := map[string]string{}
	for _, r := range asset.Renditions {
		got[string(r.Intent)] = string(r.Status)
	}
	for _, intent := range []string{"poster", "loop", "detail"} {
		if got[intent] != string(plate.RenditionStatusNotDerived) {
			t.Errorf("finalize response: %s = %q, want not_derived", intent, got[intent])
		}
	}
}

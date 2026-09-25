package plate_test

// Deleted means not served — on the owner's `original` path too. Every rendition
// intent already refused from the moment deleted_at was set, but `original`
// branched off before that check, so a deleted asset's raw bytes stayed
// downloadable until the purge sweep (hours later). The registry contract case
// Delivery/DeletedOriginalIsGone pins the same thing from the caller's side.

import (
	"net/http"
	"testing"

	"github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_DeletedAsset_OriginalRefused(t *testing.T) {
	e := newE2E(t, 720)
	assetID := e.uploadAndFinalize(harness.SynthImage(t, t.TempDir(), "o.png", 400, 300), "image/png")

	// Minted while live: a valid owner capability that downloads.
	live := e.resolve(assetID, "original")
	if live.Delivery == nil {
		t.Fatalf("precondition: original resolves while live; got %v", live.Reason)
	}
	edge := downloadPath(live.Delivery.URL)
	if status, _ := e.fetchDownload(edge); status != http.StatusFound {
		t.Fatalf("precondition: live original downloads (302); got %d", status)
	}

	if resp := e.req("DELETE", "/v1/assets/"+assetID, nil); resp.Code != 202 {
		t.Fatalf("delete: HTTP %d %s", resp.Code, resp.Body.String())
	}

	// A fresh resolve answers deleted, like every other intent.
	res := e.resolve(assetID, "original")
	if res.Delivery != nil {
		t.Fatalf("a DELETED asset's original still resolves for the owner: %s", res.Delivery.URL)
	}
	if res.Reason == nil || *res.Reason != string(plate.ReasonCodeDeleted) {
		t.Fatalf("reason = %v, want deleted", res.Reason)
	}
	// And the URL minted before the delete stops at the edge now, not at its exp.
	if status, loc := e.fetchDownload(edge); status != http.StatusForbidden {
		t.Fatalf("an original URL minted before the delete still downloads after it: %d → %s", status, loc)
	}
}

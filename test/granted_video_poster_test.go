package plate_test

// PKG-2, end to end: a GRANTED video's image-ladder intents (thumbnail, grid,
// lightbox) serve its POSTER through the bounded imgproxy ladder, signed with an
// expiry on the granted imgproxy — exactly the route public delivery takes, and
// never the raw full-resolution keyframe. Before the batch, enforceGranted sent
// these to the A/V branch, which signed a /v1/download of
// delivery/{acct}/{asset}/lightbox — an object the worker never writes — so every
// granted video image 404'd at the byte edge (this test drives that edge and
// fails there on the old code).

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	"github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_GrantedVideo_ImageIntentsServeBoundedPoster(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)
	assetID := e.uploadAndFinalize(harness.SynthVideo(t, filepath.Join(t.TempDir(), "granted.mp4"), 3*time.Second, true), "video/mp4")
	if resp := e.req("POST", "/v1/assets/"+assetID+"/renditions", mustJSON(map[string]any{"intent": "poster"})); resp.Code != 202 {
		t.Fatalf("request poster: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	e.drainWorker()
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)
	posterSrc := "/plain/s3://" + e.stor.Bucket + "/" + id.RenditionKey(id.VaultKey(e.account, assetID), "poster")

	for _, c := range []struct{ intent, device, preset string }{
		{"thumbnail", "", "thumbnail"}, {"grid", "", "grid"},
		{"lightbox", "mobile", "lightbox_mobile"}, {"lightbox", "desktop", "lightbox"},
	} {
		path := "/v1/assets/" + assetID + "/url?intent=" + c.intent + "&grant=" + grantID
		if c.device != "" {
			path += "&device=" + c.device
		}
		resp := e.req("GET", path, nil)
		if resp.Code != 200 {
			t.Fatalf("%s: HTTP %d %s", c.intent, resp.Code, resp.Body.String())
		}
		var res plateDeliveryResolution
		mustDecode(t, resp.Body.Bytes(), &res)
		if res.Delivery == nil {
			t.Fatalf("%s/%s: granted video with a ready poster refused: %s", c.intent, c.device, reasonStr(res.Reason))
		}
		u := res.Delivery.URL
		if strings.Contains(u, "/v1/download/") {
			// The old route — prove it is dead bytes, which is the bug.
			status, loc := e.fetchDownload(downloadPath(u))
			bstatus := 0
			if status == http.StatusFound {
				bstatus, _ = e.getBytes(loc)
			}
			t.Fatalf("%s/%s: granted video image intent signed as /v1/download (edge %d, bytes HTTP %d) — the worker never writes %s (PKG-2)",
				c.intent, c.device, status, bstatus, c.intent)
		}
		if res.Delivery.Mode != "granted" || !strings.HasPrefix(u, "https://granted-img.example/") ||
			!strings.Contains(u, "/pr:"+c.preset+"/exp:") || !strings.HasSuffix(u, posterSrc) {
			t.Fatalf("%s/%s: want the bounded poster (pr:%s, exp) on the granted imgproxy, sourced from the poster rendition; got mode %q %s",
				c.intent, c.device, c.preset, res.Delivery.Mode, u)
		}
		if res.Delivery.Width == nil || *res.Delivery.Width > 160 {
			t.Fatalf("%s/%s: dims %v — must come from the (160px) poster through the ladder", c.intent, c.device, res.Delivery.Width)
		}
	}

	// A grant does not change what the video's A/V intents are: detail is still
	// the signed /v1/download of the transcode, and it serves bytes.
	res := e.resolveGrant(assetID, "detail", grantID)
	if res.Delivery == nil || !strings.Contains(res.Delivery.URL, "/v1/download/") {
		t.Fatalf("granted detail changed shape: %+v", res.Delivery)
	}
	if status, _ := e.fetchDownload(downloadPath(res.Delivery.URL)); status != http.StatusFound {
		t.Fatalf("granted detail download = %d, want 302", status)
	}
}

// Poster still deriving → the granted answer is the owner path's honest
// `pending`, not a signed URL to nothing.
func TestE2E_GrantedVideo_PendingPosterIsPending(t *testing.T) {
	harness.RequireFFmpeg(t)
	e := newE2E(t, 720)
	// No poster requested and no worker run: the poster row does not exist yet.
	assetID := e.uploadAndFinalize(harness.SynthVideo(t, filepath.Join(t.TempDir(), "p.mp4"), 2*time.Second, true), "video/mp4")
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)
	for _, intent := range []string{"thumbnail", "grid", "lightbox"} {
		res := e.resolveGrant(assetID, intent, grantID)
		if res.Delivery != nil || res.Reason == nil || *res.Reason != string(plate.ReasonCodePending) {
			t.Fatalf("%s with a pending poster = %+v / %s, want delivery:null reason:pending", intent, res.Delivery, reasonStr(res.Reason))
		}
	}
}

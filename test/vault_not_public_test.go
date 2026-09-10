package plate_test

// The vault/delivery wall as a STORAGE SHAPE (spec §3.1, Q5; designer 2026-09-10):
// originals live under `vault/`, renditions under `delivery/`, and a public bucket
// policy exposes ONLY `delivery/*`. This test asserts the NEGATIVE — the property
// that makes the wall real: NO resolved delivery URL, for ANY intent, ever names
// a `vault/`-prefixed object over the public delivery base. An original is
// reachable only via the authenticated /v1/download redirect (a signed capability)
// or imgproxy's PRIVATE s3 source — never a public URL a copied link could carry.
//
// This is the deployment-level sibling of vault_no_delivery_url_test (which proves
// the VaultObject TYPE has no url field): here we prove the resolved URLs at
// runtime honor the same wall.

import (
	"strings"
	"testing"

	"github.com/chuckyatsuk/plate/internal/id"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_VaultKeyNeverInPublicDeliveryURL(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()

	// An image (imgproxy) and an A/V asset (R2 delivery prefix) — both derivation
	// routes — so we cover the two ways a delivery URL is built.
	imgID := e.uploadAndFinalize(harness.SynthImage(t, dir, "pic.png", 800, 600), "image/png")
	avID := e.uploadAndFinalize(harness.SynthVideo(t, dir+"/clip.mp4", harness.Seconds(2), true), "video/mp4")
	e.drainWorker()

	vaultPrefix := id.VaultPrefix // "vault/"

	check := func(label, url string) {
		if url == "" {
			return
		}
		// The public delivery base must never carry a vault/-prefixed path. A
		// granted A/V URL points at /v1/download (authenticated) and an image URL's
		// only vault reference is inside a PRIVATE s3:// source — neither is the
		// public delivery base naming a vault object.
		base := e.stor.Endpoint + "/" + e.stor.Bucket // the public R2/MinIO base
		if strings.Contains(url, base+"/"+vaultPrefix) {
			t.Fatalf("%s: delivery URL exposes a vault object over the PUBLIC base: %q", label, url)
		}
		// And a plain public rendition URL, if any, must be under delivery/.
		if strings.HasPrefix(url, base+"/") {
			rest := strings.TrimPrefix(url, base+"/")
			if strings.HasPrefix(rest, vaultPrefix) {
				t.Fatalf("%s: public object URL is under vault/, not delivery/: %q", label, url)
			}
		}
	}

	// Image intents.
	for _, intent := range []string{"thumbnail", "grid", "lightbox"} {
		res := e.resolve(imgID, intent)
		if res.Delivery != nil {
			check("image/"+intent, res.Delivery.URL)
		}
	}
	// A/V detail.
	if res := e.resolve(avID, "detail"); res.Delivery != nil {
		check("av/detail", res.Delivery.URL)
	}
	// The original escape hatch: a signed /v1/download URL, NOT a public vault URL.
	orig := e.resolve(imgID, "original")
	if orig.Delivery == nil {
		t.Fatal("original must resolve")
	}
	check("original", orig.Delivery.URL)
	if !strings.Contains(orig.Delivery.URL, "/v1/download/") {
		t.Fatalf("original must be the authenticated /v1/download URL, never a public vault path; got %q", orig.Delivery.URL)
	}
}

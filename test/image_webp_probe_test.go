package plate_test

// WebP uploads must be probeable (Tier 2 V2).
//
// The image probe registers decoders by blank import, and WebP is not in the
// stdlib. Without golang.org/x/image/webp, image.DecodeConfig does not
// recognise the format, finalize's header probe fails, and the upload is
// refused `409 unprobeable`. The probe being fail-closed is correct — an image
// we cannot read is not promoted — but refusing a mainstream web format is not.
//
// This test drives the REAL upload path end to end (createUpload → PUT to
// MinIO → finalize → GET asset) and asserts the probed vault dimensions, so it
// fails if the decoder registration is ever dropped: the 409 would come back.
//
// FIXTURE: a real 44-byte lossless WebP checked in at testdata/probe_64x48.webp,
// deliberately NOT synthesized in-process like the JPEG fixtures. Go has no WebP
// ENCODER (x/image is decode-only), and generating one with `ffmpeg -c:v libwebp`
// would make the test skip or fail wherever ffmpeg lacks libwebp — which is the
// case on at least one machine this was written on. A committed fixture is the
// thing actually being decoded, which is the point of the test.

import (
	"testing"
)

func TestWebPUploadIsProbeable(t *testing.T) {
	e := newE2E(t, 720)

	// Before x/image/webp was registered this finalize returned 409 unprobeable,
	// so reaching an asset id at all is half the assertion. uploadAndFinalize
	// fails the test on a non-201.
	assetID := e.uploadAndFinalize("testdata/probe_64x48.webp", "image/webp")

	resp := e.req("GET", "/v1/assets/"+assetID, nil)
	if resp.Code != 200 {
		t.Fatalf("get asset: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var asset struct {
		Kind  string `json:"kind"`
		Vault struct {
			Width     *int32  `json:"width"`
			Height    *int32  `json:"height"`
			Container *string `json:"container"`
		} `json:"vault"`
	}
	mustDecode(t, resp.Body.Bytes(), &asset)

	if asset.Kind != "image" {
		t.Fatalf("kind = %q, want image (image/webp must classify as an image)", asset.Kind)
	}
	// The REAL probed dimensions, not anything the caller declared — this is what
	// proves the decoder actually ran rather than the probe being skipped.
	if asset.Vault.Width == nil || asset.Vault.Height == nil {
		t.Fatalf("vault dimensions missing: the WebP header was not probed")
	}
	if *asset.Vault.Width != 64 || *asset.Vault.Height != 48 {
		t.Fatalf("probed %dx%d, want 64x48", *asset.Vault.Width, *asset.Vault.Height)
	}
	if asset.Vault.Container == nil || *asset.Vault.Container != "webp" {
		got := "<nil>"
		if asset.Vault.Container != nil {
			got = *asset.Vault.Container
		}
		t.Fatalf("container = %q, want webp", got)
	}
}

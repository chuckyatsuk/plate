package plate_test

// The fat-metadata probe regression (found by the demo tail backfill,
// 2026-09-13): real Photoshop-saved JPEGs stack APP1 XMP / APP13 IPTC blocks
// before the SOF marker — five real files had SOF at 86–111KiB — and the
// finalize probe reads only a bounded prefix of the object. A window smaller
// than the metadata refuses a perfectly good image as "unprobeable" (fail
// closed, but wrongly). This test builds a JPEG whose SOF sits past the OLD
// 64KiB window (padded with maximal APP1 segments, exactly the shape Photoshop
// emits) and proves the broker flow promotes it with the RIGHT probed
// dimensions — through the real service + MinIO, not a unit shim.

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"testing"
)

// fatMetadataJPEG writes a valid JPEG whose SOF is pushed past padBytes of
// APPn metadata: SOI, then maximal (64KiB-3) APP1 segments until the pad is
// reached, then the rest of a normally-encoded image. Decoders (and Plate's
// probe) must skip the APP1s to reach SOF — exactly what a Photoshop XMP/IPTC
// stack forces.
func fatMetadataJPEG(t *testing.T, path string, w, h, padBytes int) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 7), uint8(y * 5), 128, 255})
		}
	}
	var enc bytes.Buffer
	if err := jpeg.Encode(&enc, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	raw := enc.Bytes() // SOI (2 bytes) + segments…
	var out bytes.Buffer
	out.Write(raw[:2]) // SOI
	for padded := 0; padded < padBytes; {
		// APP1 with the maximum segment length (0xFFFF includes the 2 length
		// bytes): 2 marker + 2 length + 65533 payload.
		payload := 65533
		out.Write([]byte{0xFF, 0xE1})
		var ln [2]byte
		binary.BigEndian.PutUint16(ln[:], uint16(payload+2))
		out.Write(ln[:])
		out.Write(bytes.Repeat([]byte{'x'}, payload))
		padded += payload + 4
	}
	out.Write(raw[2:]) // the real segments (APP0, DQT, SOF, …, EOI)
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestE2E_FinalizePromotesJPEGWithSOFPast64KiB(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	src := filepath.Join(dir, "fatmeta.jpg")
	// Two maximal APP1 segments ≈ 128KiB of metadata before SOF — past the old
	// 64KiB window, within the current one.
	fatMetadataJPEG(t, src, 320, 200, 128*1024)

	assetID := e.uploadAndFinalize(src, "image/jpeg")

	// The probe must have read the REAL dimensions from behind the metadata —
	// a promoted asset with wrong/absent dims would poison every delivery clamp.
	resp := e.req("GET", "/v1/assets/"+assetID, nil)
	if resp.Code != 200 {
		t.Fatalf("getAsset: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var got struct {
		Vault struct {
			Width  *int32 `json:"width"`
			Height *int32 `json:"height"`
		} `json:"vault"`
	}
	mustDecode(t, resp.Body.Bytes(), &got)
	if got.Vault.Width == nil || got.Vault.Height == nil || *got.Vault.Width != 320 || *got.Vault.Height != 200 {
		t.Fatalf("fat-metadata JPEG promoted with wrong dims: %v x %v, want 320 x 200", got.Vault.Width, got.Vault.Height)
	}
}

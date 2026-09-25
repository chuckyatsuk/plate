package service

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// Uri's site (uriaran.com) PERSISTS the public delivery URLs Plate hands back and
// they are CDN-cached for a year. TestPublicImageURL_Golden pins the signer; this
// pins the WHOLE public resolve response, through the router, the (unbound,
// legacy) token verifier and the delivery handler, for every public (kind,
// intent, device) cell Uri can reach — image ladder + zoom, and a video's
// poster-ladder and A/V intents. The golden bodies were recorded from the code
// BEFORE the security batch (key-binding, provisioning, granted-video poster,
// owner-original deleted check); any byte of difference fails here.
//
// Re-record (only for an intended, announced public-shape change):
//
//	PLATE_GOLDEN_RECORD=1 go test ./internal/service -run TestPublicResolve_Golden -v
func TestPublicResolve_Golden(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	st := newStubStore()
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	st.put(plate.Asset{
		Id: "01M2KWA9BQ645WM87MZ4TENG8F", Account: "uriaran", Kind: plate.Image, Created: created,
		Vault: plate.VaultObject{Key: "vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F", Width: i32(6000), Height: i32(4000)},
	})
	ready := plate.RenditionStatus("ready")
	st.put(plate.Asset{
		Id: "01M2KWA9BQ645WM87MZ4VIDEO0", Account: "uriaran", Kind: plate.Video, Created: created,
		Vault: plate.VaultObject{Key: "vault/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0", Width: i32(3840), Height: i32(2160)},
		Renditions: []plate.Rendition{
			{Intent: plate.Poster, Status: ready, Width: i32(3840), Height: i32(2160)},
			{Intent: plate.Detail, Status: ready},
			{Intent: plate.Loop, Status: plate.RenditionStatus("pending")},
		},
	})
	h := stubService(t, st, auth.NewVerifier(pub, "", "")).Router()
	tok := stubToken(t, priv, "uriaran", "assets:read")

	var cells []string
	for _, dev := range []string{"", "mobile", "desktop"} {
		for _, in := range []string{"thumbnail", "grid", "lightbox", "zoom_1", "zoom_2", "zoom_3"} {
			cells = append(cells, fmt.Sprintf("01M2KWA9BQ645WM87MZ4TENG8F|%s|%s", in, dev))
		}
		for _, in := range []string{"thumbnail", "grid", "lightbox", "zoom_1", "poster", "detail", "loop"} {
			cells = append(cells, fmt.Sprintf("01M2KWA9BQ645WM87MZ4VIDEO0|%s|%s", in, dev))
		}
	}
	got := map[string]string{}
	for _, c := range cells {
		var id, in, dev string
		fmt.Sscanf(replaceBars(c), "%s %s %s", &id, &in, &dev)
		path := "/v1/assets/" + id + "/url?intent=" + in
		if dev != "" {
			path += "&device=" + dev
		}
		rec := do(t, h, "GET", path, tok)
		got[c] = fmt.Sprintf("%d %s", rec.Code, trimBody(rec))
	}

	if os.Getenv("PLATE_GOLDEN_RECORD") != "" {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("\t%q: %q,\n", k, got[k])
		}
		return
	}
	if len(publicResolveGolden) != len(got) {
		t.Fatalf("golden has %d cells, resolved %d", len(publicResolveGolden), len(got))
	}
	for k, want := range publicResolveGolden {
		if got[k] != want {
			t.Errorf("%s: public resolve changed — Uri's persisted URLs would diverge:\n got %s\nwant %s", k, got[k], want)
		}
	}
}

func replaceBars(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == '|' {
			b[i] = ' '
		}
	}
	// An empty device leaves a trailing space; Sscanf then leaves dev "".
	return string(b)
}

// Recorded from fc326df (pre-batch) with PLATE_GOLDEN_RECORD=1.
var publicResolveGolden = map[string]string{
	"01M2KWA9BQ645WM87MZ4TENG8F|grid|":             "200 {\"delivery\":{\"height\":533,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/xWAn8joP_B1PAAIwuo9Wk2FxWtjDyxpz387cvKfeXRs/grid/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":800},\"intent\":\"grid\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|grid|desktop":      "200 {\"delivery\":{\"height\":533,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/xWAn8joP_B1PAAIwuo9Wk2FxWtjDyxpz387cvKfeXRs/grid/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":800},\"intent\":\"grid\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|grid|mobile":       "200 {\"delivery\":{\"height\":533,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/xWAn8joP_B1PAAIwuo9Wk2FxWtjDyxpz387cvKfeXRs/grid/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":800},\"intent\":\"grid\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|lightbox|":         "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"lightbox\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|lightbox|desktop":  "200 {\"delivery\":{\"height\":1365,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/ZOEoHu7Z0DzVm_epX4nYkhwngZJpqOk8NhZNjyRRmuU/lightbox/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":2048},\"intent\":\"lightbox\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|lightbox|mobile":   "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"lightbox\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|thumbnail|":        "200 {\"delivery\":{\"height\":267,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/E6vJTUwEk5pjbK0EXn_n70YhVb1nmPHMG_Q3UDc798c/thumbnail/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":400},\"intent\":\"thumbnail\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|thumbnail|desktop": "200 {\"delivery\":{\"height\":267,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/E6vJTUwEk5pjbK0EXn_n70YhVb1nmPHMG_Q3UDc798c/thumbnail/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":400},\"intent\":\"thumbnail\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|thumbnail|mobile":  "200 {\"delivery\":{\"height\":267,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/E6vJTUwEk5pjbK0EXn_n70YhVb1nmPHMG_Q3UDc798c/thumbnail/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":400},\"intent\":\"thumbnail\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_1|":           "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"zoom_1\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_1|desktop":    "200 {\"delivery\":{\"height\":2048,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/xd2t8cLm46MUj2Kp_Nv5thQ2dzuTiazMrMSfbLwM2Oc/zoom_1/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":3072},\"intent\":\"zoom_1\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_1|mobile":     "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"zoom_1\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_2|":           "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"zoom_2\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_2|desktop":    "200 {\"delivery\":{\"height\":2731,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/jwqWchWPlteQSbU235SP4PkWDldz4n8jI5jEF1ZSN24/zoom_2/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":4096},\"intent\":\"zoom_2\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_2|mobile":     "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"zoom_2\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_3|":           "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"zoom_3\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_3|desktop":    "200 {\"delivery\":{\"height\":3651,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/MmH2piZyZ2kouMAeaGvHODCO94KrnU2Uh8vX23c_wH4/zoom_3_standard/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":5477},\"intent\":\"zoom_3\"}",
	"01M2KWA9BQ645WM87MZ4TENG8F|zoom_3|mobile":     "200 {\"delivery\":{\"height\":933,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F\",\"width\":1400},\"intent\":\"zoom_3\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|detail|":           "200 {\"delivery\":{\"mode\":\"public\",\"url\":\"https://r2.example/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/detail\"},\"intent\":\"detail\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|detail|desktop":    "200 {\"delivery\":{\"mode\":\"public\",\"url\":\"https://r2.example/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/detail\"},\"intent\":\"detail\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|detail|mobile":     "200 {\"delivery\":{\"mode\":\"public\",\"url\":\"https://r2.example/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/detail\"},\"intent\":\"detail\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|grid|":             "200 {\"delivery\":{\"height\":450,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/g1COIv6sTf7kPGaYH0uS-45cbsIuoPQSaKN7DAHRwjU/grid/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":800},\"intent\":\"grid\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|grid|desktop":      "200 {\"delivery\":{\"height\":450,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/g1COIv6sTf7kPGaYH0uS-45cbsIuoPQSaKN7DAHRwjU/grid/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":800},\"intent\":\"grid\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|grid|mobile":       "200 {\"delivery\":{\"height\":450,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/g1COIv6sTf7kPGaYH0uS-45cbsIuoPQSaKN7DAHRwjU/grid/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":800},\"intent\":\"grid\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|lightbox|":         "200 {\"delivery\":{\"height\":788,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/zUIx7L0H6tTstEbOFAOs8CF74sXV7VgoyKzxYbMxr1g/lightbox_mobile/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":1400},\"intent\":\"lightbox\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|lightbox|desktop":  "200 {\"delivery\":{\"height\":1152,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/hytZwRQrcSTEvciYPbN2bOI0dsNYJUYRF-UhZ2IwG1Y/lightbox/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":2048},\"intent\":\"lightbox\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|lightbox|mobile":   "200 {\"delivery\":{\"height\":788,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/zUIx7L0H6tTstEbOFAOs8CF74sXV7VgoyKzxYbMxr1g/lightbox_mobile/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":1400},\"intent\":\"lightbox\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|loop|":             "200 {\"delivery\":null,\"intent\":\"loop\",\"reason\":\"pending\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|loop|desktop":      "200 {\"delivery\":null,\"intent\":\"loop\",\"reason\":\"pending\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|loop|mobile":       "200 {\"delivery\":null,\"intent\":\"loop\",\"reason\":\"pending\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|poster|":           "200 {\"delivery\":{\"mode\":\"public\",\"url\":\"https://r2.example/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\"},\"intent\":\"poster\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|poster|desktop":    "200 {\"delivery\":{\"mode\":\"public\",\"url\":\"https://r2.example/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\"},\"intent\":\"poster\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|poster|mobile":     "200 {\"delivery\":{\"mode\":\"public\",\"url\":\"https://r2.example/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\"},\"intent\":\"poster\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|thumbnail|":        "200 {\"delivery\":{\"height\":225,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/vMJKU91GNJZVwZXK6W0q5G4fKPZ4aMVUIcz2bikGc4M/thumbnail/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":400},\"intent\":\"thumbnail\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|thumbnail|desktop": "200 {\"delivery\":{\"height\":225,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/vMJKU91GNJZVwZXK6W0q5G4fKPZ4aMVUIcz2bikGc4M/thumbnail/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":400},\"intent\":\"thumbnail\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|thumbnail|mobile":  "200 {\"delivery\":{\"height\":225,\"mode\":\"public\",\"url\":\"https://plate-img.everysinglefile.com/vMJKU91GNJZVwZXK6W0q5G4fKPZ4aMVUIcz2bikGc4M/thumbnail/plain/s3://plate/delivery/uriaran/01M2KWA9BQ645WM87MZ4VIDEO0/poster\",\"width\":400},\"intent\":\"thumbnail\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|zoom_1|":           "200 {\"delivery\":null,\"intent\":\"zoom_1\",\"reason\":\"pending\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|zoom_1|desktop":    "200 {\"delivery\":null,\"intent\":\"zoom_1\",\"reason\":\"pending\"}",
	"01M2KWA9BQ645WM87MZ4VIDEO0|zoom_1|mobile":     "200 {\"delivery\":null,\"intent\":\"zoom_1\",\"reason\":\"pending\"}",
}

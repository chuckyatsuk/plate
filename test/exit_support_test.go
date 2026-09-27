package plate_test

// Exit support (the registry's Exit job reads an account's media through
// exports and listAssets). Four gaps, each pinned end to end against the REAL
// service (HTTP handlers + Postgres + MinIO + the worker):
//
//   P1  CreateExport counted owned rows against len(assets): a duplicated id or
//       one PURGED asset refused the whole set 403, and a deleted-but-unpurged
//       asset was accepted into the frozen set. It now classifies like
//       CreateGrant: distinct ids; the caller's deleted/purged ids are left out
//       and reported in gone_assets; a foreign or never-existed id still
//       refuses the whole set with the same indistinguishable 403.
//   P2  The export download edge did not re-check deleted_at, so an export URL
//       minted while an asset was live kept serving its bytes after the owner
//       deleted it (until the export expired). The owner-original branch
//       already refused; the export branch now does too.
//   P3  (A/V half; the sweep half is in checksum_sweep_test.go) Plate never
//       computed a checksum itself. The derive job now hashes the original
//       while it downloads it and records sha256:<hex> verified;
//       checksum_verified is exposed on the vault object.
//   P4  content_type was stored on the upload row but never exposed on Asset.
//
// Everything here reads responses as raw JSON, so it compiles against the
// pre-batch code too — which is how each test was proven to fail there.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/test/harness"
)

// exportCreateOut is the createExport response as a caller decodes it.
type exportCreateOut struct {
	ID         string    `json:"id"`
	Assets     []string  `json:"assets"`
	GoneAssets *[]string `json:"gone_assets"`
	Downloads  []struct {
		Asset string `json:"asset"`
		URL   string `json:"url"`
	} `json:"downloads"`
}

func (e *e2e) tryExport(assets ...string) (int, exportCreateOut, string) {
	e.t.Helper()
	body := mustJSON(map[string]any{"assets": assets, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
	resp := e.req("POST", "/v1/exports", body)
	var out exportCreateOut
	if resp.Code == http.StatusCreated {
		mustDecode(e.t, resp.Body.Bytes(), &out)
	}
	return resp.Code, out, resp.Body.String()
}

// assetJSON reads GET /v1/assets/{id} as a raw map, so a test can assert on a
// field whether or not the generated type (or the old code) has it.
func (e *e2e) assetJSON(assetID string) map[string]any {
	e.t.Helper()
	resp := e.req("GET", "/v1/assets/"+assetID, nil)
	if resp.Code != http.StatusOK {
		e.t.Fatalf("getAsset %s: HTTP %d %s", assetID, resp.Code, resp.Body.String())
	}
	var m map[string]any
	mustDecode(e.t, resp.Body.Bytes(), &m)
	return m
}

func vaultOf(t *testing.T, a map[string]any) map[string]any {
	t.Helper()
	v, ok := a["vault"].(map[string]any)
	if !ok {
		t.Fatalf("asset has no vault object: %v", a)
	}
	return v
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// ── P1 ──────────────────────────────────────────────────────────────────────

func TestE2E_CreateExport_GoneAssetsLeftOutAndReported(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	live := e.uploadAndFinalize(harness.SynthImage(t, dir, "live.png", 320, 240), "image/png")
	live2 := e.uploadAndFinalize(harness.SynthImage(t, dir, "live2.png", 320, 240), "image/png")
	deleted := e.uploadAndFinalize(harness.SynthImage(t, dir, "deleted.png", 320, 240), "image/png")
	purged := e.uploadAndFinalize(harness.SynthImage(t, dir, "purged.png", 320, 240), "image/png")
	e.deleteAndPurge(purged)
	if resp := e.req("DELETE", "/v1/assets/"+deleted, nil); resp.Code != 202 {
		t.Fatalf("delete: %d", resp.Code)
	}

	// Duplicates, a deleted and a purged id, in a deliberate order.
	code, x, body := e.tryExport(live2, purged, live, deleted, live2)
	if code != http.StatusCreated {
		t.Fatalf("export over {live, live, deleted, purged, dup} = %d %s — one gone asset (or a duplicate) killed the whole set", code, body)
	}
	if !reflect.DeepEqual(x.Assets, []string{live2, live}) {
		t.Fatalf("export froze %v, want only the live ids, once each, in request order [%s %s]", x.Assets, live2, live)
	}
	if x.GoneAssets == nil || !reflect.DeepEqual(*x.GoneAssets, []string{purged, deleted}) {
		t.Fatalf("gone_assets = %v, want the purged and deleted ids in request order [%s %s]", x.GoneAssets, purged, deleted)
	}
	if len(x.Downloads) != 2 {
		t.Fatalf("export must carry one download per LIVE asset (2); got %d: %+v", len(x.Downloads), x.Downloads)
	}
	for _, d := range x.Downloads {
		if d.Asset == deleted || d.Asset == purged {
			t.Fatalf("export hands out a download for gone asset %s", d.Asset)
		}
		if status, _ := e.fetchDownload(downloadPath(d.URL)); status != http.StatusFound {
			t.Fatalf("live export download for %s = %d, want 302", d.Asset, status)
		}
	}

	// GET re-derives from the frozen set: still only the live ids.
	resp := e.req("GET", "/v1/exports/"+x.ID, nil)
	var got exportCreateOut
	mustDecode(t, resp.Body.Bytes(), &got)
	if !reflect.DeepEqual(got.Assets, []string{live2, live}) || len(got.Downloads) != 2 {
		t.Fatalf("getExport = assets %v, %d downloads; want the live set only", got.Assets, len(got.Downloads))
	}
	if got.GoneAssets != nil {
		t.Fatalf("gone_assets is a createExport-response field; getExport carries %v", *got.GoneAssets)
	}

	// Nothing gone: no gone_assets at all.
	if _, x2, _ := e.tryExport(live); x2.GoneAssets != nil {
		t.Fatalf("all-live export carries gone_assets %v", *x2.GoneAssets)
	}
}

func TestE2E_CreateExport_DuplicateIDsCoveredOnce(t *testing.T) {
	e := newE2E(t, 720)
	live := e.uploadAndFinalize(harness.SynthImage(t, t.TempDir(), "a.png", 320, 240), "image/png")
	code, x, body := e.tryExport(live, live, live)
	if code != http.StatusCreated {
		t.Fatalf("export naming one asset three times = %d %s, want 201", code, body)
	}
	if !reflect.DeepEqual(x.Assets, []string{live}) || len(x.Downloads) != 1 {
		t.Fatalf("export = assets %v, %d downloads; want [%s] once with one download", x.Assets, len(x.Downloads), live)
	}
}

func TestE2E_CreateExport_AllGoneIsANamedRefusal(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	deleted := e.uploadAndFinalize(harness.SynthImage(t, dir, "d.png", 320, 240), "image/png")
	purged := e.uploadAndFinalize(harness.SynthImage(t, dir, "p.png", 320, 240), "image/png")
	e.deleteAndPurge(purged)
	if resp := e.req("DELETE", "/v1/assets/"+deleted, nil); resp.Code != 202 {
		t.Fatalf("delete: %d", resp.Code)
	}
	for _, set := range [][]string{{deleted}, {purged}, {deleted, purged, deleted}} {
		code, _, body := e.tryExport(set...)
		if code != http.StatusConflict || !strings.Contains(body, `"assets_gone"`) {
			t.Fatalf("export over only-gone ids %v = %d %s, want 409 assets_gone", set, code, body)
		}
	}
}

// A foreign or never-existed id still refuses the whole set, with one body for
// both, naming no id — and a gone own id beside it changes nothing.
func TestE2E_CreateExport_ForeignStillRefusesWholeSet(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()
	own := e.uploadAndFinalize(harness.SynthImage(t, dir, "own.png", 320, 240), "image/png")
	purged := e.uploadAndFinalize(harness.SynthImage(t, dir, "purged.png", 320, 240), "image/png")
	e.deleteAndPurge(purged)

	const b = "export-b-acct"
	if err := e.st.CreateAccount(ctx, b, "", ""); err != nil {
		t.Fatal(err)
	}
	aTok, aAcct := e.token, e.account
	e.token, e.account = signToken(t, e.priv, b, "assets:read,assets:write,grants:manage,assets:export"), b
	foreign := e.uploadAndFinalize(harness.SynthImage(t, dir, "b.png", 320, 240), "image/png")
	foreignDeleted := e.uploadAndFinalize(harness.SynthImage(t, dir, "bd.png", 320, 240), "image/png")
	foreignPurged := e.uploadAndFinalize(harness.SynthImage(t, dir, "bp.png", 320, 240), "image/png")
	e.deleteAndPurge(foreignPurged)
	if resp := e.req("DELETE", "/v1/assets/"+foreignDeleted, nil); resp.Code != 202 {
		t.Fatalf("delete: %d", resp.Code)
	}
	e.token, e.account = aTok, aAcct

	var bodies []string
	for _, set := range [][]string{
		{own, foreign},
		{own, "01NEVEREXISTED0000000000000"},
		{own, purged, foreign},
		{own, foreignPurged},
		{own, foreignDeleted},
		{purged, foreign}, // gone own + foreign: still the 403, not assets_gone
	} {
		code, _, body := e.tryExport(set...)
		if code != http.StatusForbidden {
			t.Fatalf("export over %v = %d %s, want 403 for the whole set", set, code, body)
		}
		for _, id := range []string{foreign, foreignDeleted, foreignPurged, b} {
			if strings.Contains(body, id) {
				t.Fatalf("refusal body names %q: %s", id, body)
			}
		}
		bodies = append(bodies, body)
	}
	for _, other := range bodies[1:] {
		if other != bodies[0] {
			t.Fatalf("refusals differ (an existence oracle): %q vs %q", bodies[0], other)
		}
	}
}

// ── P2 ──────────────────────────────────────────────────────────────────────

func TestE2E_Export_DeletedAssetRefusedAtEdge(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	doomed := e.uploadAndFinalize(harness.SynthImage(t, dir, "doomed.png", 320, 240), "image/png")
	keep := e.uploadAndFinalize(harness.SynthImage(t, dir, "keep.png", 320, 240), "image/png")
	code, x, body := e.tryExport(doomed, keep)
	if code != http.StatusCreated {
		t.Fatalf("createExport: %d %s", code, body)
	}
	urls := map[string]string{}
	for _, d := range x.Downloads {
		urls[d.Asset] = downloadPath(d.URL)
	}
	for _, a := range []string{doomed, keep} {
		if status, _ := e.fetchDownload(urls[a]); status != http.StatusFound {
			t.Fatalf("precondition: live export download for %s = %d, want 302", a, status)
		}
	}

	if resp := e.req("DELETE", "/v1/assets/"+doomed, nil); resp.Code != 202 {
		t.Fatalf("delete: HTTP %d %s", resp.Code, resp.Body.String())
	}

	// The URL minted while the asset was live stops at the delete — not at the
	// export's expiry, and not when the sweep removes the bytes.
	if status, loc := e.fetchDownload(urls[doomed]); status != http.StatusForbidden {
		t.Fatalf("an export URL for a DELETED asset still downloads: %d → %s", status, loc)
	}
	// The rest of the export is untouched.
	if status, _ := e.fetchDownload(urls[keep]); status != http.StatusFound {
		t.Fatalf("the export's live asset stopped downloading after another was deleted: %d", status)
	}
	// And after the purge, still refused (no row at all now).
	e.deleteAndPurge(doomed)
	if status, _ := e.fetchDownload(urls[doomed]); status != http.StatusForbidden {
		t.Fatalf("export URL for a PURGED asset = %d, want 403", status)
	}
}

// ── P3 (A/V: hashed while the derive job downloads the original) ────────────

func TestE2E_Checksum_VideoHashedByDeriveJob(t *testing.T) {
	e := newE2E(t, 720)
	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "v.mp4"), harness.Seconds(2), true)
	want := sha256File(t, src)
	assetID := e.uploadAndFinalize(src, "video/mp4") // no valid md5 claim: unverified at finalize

	v := vaultOf(t, e.assetJSON(assetID))
	if v["checksum"] != "" || v["checksum_verified"] != false {
		t.Fatalf("before the worker ran: vault checksum %v verified %v, want empty + false", v["checksum"], v["checksum_verified"])
	}

	e.drainWorker() // the detail derive job downloads the original

	v = vaultOf(t, e.assetJSON(assetID))
	if v["checksum"] != want {
		t.Fatalf("after the derive job: vault checksum = %v, want %s (the sha256 of the stored bytes)", v["checksum"], want)
	}
	if v["checksum_verified"] != true {
		t.Fatalf("after the derive job: checksum_verified = %v, want true", v["checksum_verified"])
	}
}

// ── P4 ──────────────────────────────────────────────────────────────────────

func TestE2E_Asset_ExposesContentType(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()
	png := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 64, 48), "image/png")
	finalized := string(e.lastFinalizeBody)
	vid := e.uploadAndFinalize(harness.SynthVideo(t, filepath.Join(dir, "v.mp4"), harness.Seconds(1), false), "video/mp4")

	if !strings.Contains(finalized, `"content_type":"image/png"`) {
		t.Fatalf("finalize response lacks content_type image/png: %s", finalized)
	}
	for id, want := range map[string]string{png: "image/png", vid: "video/mp4"} {
		if got := e.assetJSON(id)["content_type"]; got != want {
			t.Fatalf("getAsset %s content_type = %v, want %s", id, got, want)
		}
	}

	// listAssets carries it too (the Exit manifest pages through this).
	resp := e.req("GET", "/v1/assets?limit=200", nil)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	mustDecode(t, resp.Body.Bytes(), &page)
	seen := 0
	for _, it := range page.Items {
		if it["id"] == png && it["content_type"] == "image/png" {
			seen++
		}
		if it["id"] == vid && it["content_type"] == "video/mp4" {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("listAssets does not carry content_type for both assets: %s", resp.Body.String())
	}

	// deleteAsset's response is an asset too.
	del := e.req("DELETE", "/v1/assets/"+png, nil)
	if !strings.Contains(del.Body.String(), `"content_type":"image/png"`) {
		t.Fatalf("deleteAsset response lacks content_type: %s", del.Body.String())
	}

	// An asset with no upload row (seeded, never brokered): no content_type,
	// never one guessed from kind.
	const seeded = "01SEEDEDNOUPLOADROW0000000"
	if _, err := e.st.Pool().Exec(ctx, `
		INSERT INTO assets (id, account, kind, vault_key, vault_checksum, vault_size_bytes)
		VALUES ($1, $2, 'image', $3, '', 10)`, seeded, e.account, "vault/"+e.account+"/"+seeded); err != nil {
		t.Fatal(err)
	}
	a := e.assetJSON(seeded)
	if _, has := a["content_type"]; has {
		t.Fatalf("an asset with no upload row must omit content_type; got %v", a["content_type"])
	}
	if _, has := vaultOf(t, a)["checksum_verified"]; !has {
		t.Fatalf("vault.checksum_verified must always be present: %v", a["vault"])
	}
}

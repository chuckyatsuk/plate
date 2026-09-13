package plate_test

// The export capability (Tier 1), proven end to end in the REAL service
// (HTTP handlers + Postgres exports table + signer + the /v1/download byte edge
// + MinIO). An export is the owner's long-lived, revocable route to ORIGINAL
// bytes — the Plate-native shape for a consumer's export/manifest links, and
// the capability that gates removing R2-direct from Files. What must hold:
//
//   - a live export yields signed /v1/download URLs that, fetched WITHOUT a
//     token (the signature is the authorization), 302 to a presigned GET that
//     serves the EXACT original bytes;
//   - REVOCATION is immediate at the byte edge — no cache window, unlike
//     grants: the very next fetch of an already-issued URL is refused;
//   - expiry is enforced at the edge even for an already-issued URL;
//   - the capability domains stay separate: an export signature cannot be
//     replayed as an owner-original or grant URL (and vice versa), cannot be
//     re-pointed at another intent or export id, and creation over an asset the
//     caller does not own is refused wholesale;
//   - the TTL is bounded at issue: past the cap (or not in the future) is a 400;
//   - GET re-derives the same URLs while live, and a revoked export is returned
//     bare — reading it never resurrects the capability.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/test/harness"
)

// exportOut is the response shape the export tests assert on.
type exportOut struct {
	ID        string  `json:"id"`
	RevokedAt *string `json:"revoked_at"`
	Downloads []struct {
		Asset   string `json:"asset"`
		URL     string `json:"url"`
		Expires string `json:"expires"`
	} `json:"downloads"`
}

// createExport issues an export over the given assets via the real POST
// /v1/exports endpoint and returns the decoded response.
func (e *e2e) createExport(t *testing.T, exp time.Time, assets ...string) exportOut {
	t.Helper()
	body := mustJSON(map[string]any{"assets": assets, "expires": exp.UTC().Format(time.RFC3339Nano)})
	resp := e.req("POST", "/v1/exports", body)
	if resp.Code != 201 {
		t.Fatalf("createExport: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var out exportOut
	mustDecode(t, resp.Body.Bytes(), &out)
	return out
}

func TestE2E_Export_LiveExport_ServesOriginalBytes(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	img := harness.SynthImage(t, dir, "orig.png", 400, 300)
	want, err := readFile(img)
	if err != nil {
		t.Fatal(err)
	}
	assetID := e.uploadAndFinalize(img, "image/png")

	out := e.createExport(t, time.Now().Add(7*24*time.Hour), assetID)
	if len(out.Downloads) != 1 || out.Downloads[0].Asset != assetID {
		t.Fatalf("export must carry one download per asset; got %+v", out.Downloads)
	}
	u := out.Downloads[0].URL
	// The URL is a signed Plate download capability over the VAULT key — long
	// TTL lives in Plate's HMAC, never in a storage-presigned URL.
	if !strings.Contains(u, "/v1/download/vault/") || !strings.Contains(u, "export="+out.ID) || !strings.Contains(u, "sig=") {
		t.Fatalf("export download must be a signed /v1/download vault URL carrying its export id; got %q", u)
	}

	// Fetch WITHOUT a token: 302 → presigned GET → the exact original bytes.
	status, loc := e.fetchDownload(downloadPath(u))
	if status != 302 {
		t.Fatalf("live export download must 302; got %d", status)
	}
	bstatus, got := e.getBytes(loc)
	if bstatus != 200 {
		t.Fatalf("export presigned target must serve bytes; got HTTP %d", bstatus)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("export must serve the EXACT original bytes; got %d bytes, want %d", len(got), len(want))
	}
}

func TestE2E_Export_RevocationImmediatelyKillsIssuedURL(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	assetID := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 400, 300), "image/png")
	out := e.createExport(t, time.Now().Add(24*time.Hour), assetID)
	dl := downloadPath(out.Downloads[0].URL)

	// Live first — the URL genuinely worked before revocation.
	if status, _ := e.fetchDownload(dl); status != 302 {
		t.Fatalf("pre-revocation export download must 302; got %d", status)
	}

	resp := e.req("DELETE", "/v1/exports/"+out.ID, nil)
	if resp.Code != 200 {
		t.Fatalf("revokeExport: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var revoked exportOut
	mustDecode(t, resp.Body.Bytes(), &revoked)
	if revoked.RevokedAt == nil {
		t.Fatalf("revoked export must carry revoked_at")
	}
	if len(revoked.Downloads) != 0 {
		t.Fatalf("revoked export must not hand out downloads; got %+v", revoked.Downloads)
	}

	// IMMEDIATELY refused — the export edge has no verdict cache (the deliberate
	// difference from granted A/V, whose revocation waits out one cache window).
	if status, _ := e.fetchDownload(dl); status != 403 {
		t.Fatalf("revoked export URL must be refused on the very next fetch; got %d", status)
	}

	// And a GET of the revoked export stays bare — reading never resurrects it.
	getResp := e.req("GET", "/v1/exports/"+out.ID, nil)
	if getResp.Code != 200 {
		t.Fatalf("getExport after revoke: HTTP %d", getResp.Code)
	}
	var after exportOut
	mustDecode(t, getResp.Body.Bytes(), &after)
	if len(after.Downloads) != 0 || after.RevokedAt == nil {
		t.Fatalf("revoked export must read back bare with revoked_at; got %+v", after)
	}
}

func TestE2E_Export_ExpiryEnforcedAtEdge(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	assetID := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 400, 300), "image/png")
	out := e.createExport(t, time.Now().Add(24*time.Hour), assetID)
	dl := downloadPath(out.Downloads[0].URL)

	// Expire the row behind the issued URL (creation refuses past expiries, so
	// simulate time passing directly). The edge's live SQL check must refuse even
	// though the URL's own signature window may not have elapsed in lockstep.
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE exports SET expires = now() - interval '1 minute' WHERE id = $1`, out.ID); err != nil {
		t.Fatalf("expire export row: %v", err)
	}
	if status, _ := e.fetchDownload(dl); status != 403 {
		t.Fatalf("expired export URL must be refused at the edge; got %d", status)
	}
}

func TestE2E_Export_DomainSeparation(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	assetID := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 400, 300), "image/png")
	out := e.createExport(t, time.Now().Add(24*time.Hour), assetID)
	dl := downloadPath(out.Downloads[0].URL)

	// Re-pointing the URL at another export id breaks the signature.
	swapped := strings.Replace(dl, "export="+out.ID, "export=01FORGEDEXPORTIDXXXXXXXXXX", 1)
	if status, _ := e.fetchDownload(swapped); status != 403 {
		t.Fatalf("export URL with a swapped export id must be refused; got %d", status)
	}
	// Re-pointing it at a non-original intent breaks the signature — an export
	// can never serve a rendition.
	reIntent := strings.Replace(dl, "intent=original", "intent=detail", 1)
	if status, _ := e.fetchDownload(reIntent); status != 403 {
		t.Fatalf("export URL re-pointed at a rendition intent must be refused; got %d", status)
	}
	// Smuggling a grant parameter onto an export URL is refused outright.
	if status, _ := e.fetchDownload(dl + "&grant=01SOMEGRANTIDXXXXXXXXXXXXX"); status != 403 {
		t.Fatalf("export URL carrying a grant param must be refused; got %d", status)
	}

	// The OWNER-original capability cannot be replayed as an export: take a real
	// owner original URL and claim an export id — the contexts differ, so the
	// signature no longer verifies.
	res := e.resolve(assetID, "original")
	if res.Delivery == nil {
		t.Fatalf("original must resolve for the owner")
	}
	ownerAsExport := downloadPath(res.Delivery.URL) + "&export=" + out.ID
	if status, _ := e.fetchDownload(ownerAsExport); status != 403 {
		t.Fatalf("an owner-original URL replayed as an export must be refused; got %d", status)
	}
}

func TestE2E_Export_IssueBounds(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	assetID := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 400, 300), "image/png")

	// Past the 30-day cap → 400. "Long-lived" is bounded at issue, always.
	tooLong := mustJSON(map[string]any{"assets": []string{assetID},
		"expires": time.Now().Add(31 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)})
	if resp := e.req("POST", "/v1/exports", tooLong); resp.Code != 400 {
		t.Fatalf("expires past the cap must be a 400; got %d: %s", resp.Code, resp.Body.String())
	}
	// Not in the future → 400.
	past := mustJSON(map[string]any{"assets": []string{assetID},
		"expires": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)})
	if resp := e.req("POST", "/v1/exports", past); resp.Code != 400 {
		t.Fatalf("past expires must be a 400; got %d", resp.Code)
	}
	// An asset the caller does not own (or that does not exist) refuses the whole
	// export — no partial export, no leak of which asset was foreign.
	foreign := mustJSON(map[string]any{"assets": []string{assetID, "01NOTOWNEDBYTHISACCOUNTXXX"},
		"expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
	if resp := e.req("POST", "/v1/exports", foreign); resp.Code != 403 {
		t.Fatalf("export over a foreign/missing asset must be refused (403); got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestE2E_Export_GetRederivesSameURLs(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	assetID := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 400, 300), "image/png")
	out := e.createExport(t, time.Now().Add(24*time.Hour), assetID)

	resp := e.req("GET", "/v1/exports/"+out.ID, nil)
	if resp.Code != 200 {
		t.Fatalf("getExport: HTTP %d", resp.Code)
	}
	var got exportOut
	mustDecode(t, resp.Body.Bytes(), &got)
	if len(got.Downloads) != 1 || got.Downloads[0].URL != out.Downloads[0].URL {
		t.Fatalf("getExport must re-derive the SAME download URL (a pure function of the export, never stored):\ncreate: %q\nget:    %q",
			out.Downloads[0].URL, got.Downloads[0].URL)
	}
}

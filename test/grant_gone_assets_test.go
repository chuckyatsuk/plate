package plate_test

// Item 6: one gone asset must not kill a whole grant.
//
// What CreateGrant did before the batch, by case (each pinned below):
//   (a) the caller's own DELETED asset (row present, deleted_at set) → counted as
//       owned → the grant was CREATED, and resolving it answered reason:deleted.
//   (b) the caller's own PURGED asset (the sweep removed the row) → not counted →
//       ErrForeignAsset → 403 for the WHOLE set: the registry symptom (every
//       image in the share dies, the ZIP 503s forever).
//   (c) a foreign or never-existing id → 403, indistinguishable. Correct.
// Also: a set naming the same id twice → counted once → 403.
//
// Now: (a) and (b) behave the same — the grant covers the full requested set,
// the gone ids come back in gone_assets, and resolving one answers `deleted`
// whether or not the sweep has run. (c) is unchanged: 403, no id named.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/worker"
	"github.com/chuckyatsuk/plate/test/harness"
)

type grantOut struct {
	ID         string    `json:"id"`
	Assets     []string  `json:"assets"`
	GoneAssets *[]string `json:"gone_assets"`
}

func (e *e2e) tryGrant(assets ...string) (int, grantOut, string) {
	e.t.Helper()
	body := mustJSON(map[string]any{"assets": assets, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
	resp := e.req("POST", "/v1/grants", body)
	var g grantOut
	if resp.Code == http.StatusCreated {
		if err := json.Unmarshal(resp.Body.Bytes(), &g); err != nil {
			e.t.Fatal(err)
		}
	}
	return resp.Code, g, resp.Body.String()
}

func (e *e2e) deleteAndPurge(assetIDs ...string) {
	e.t.Helper()
	for _, a := range assetIDs {
		if resp := e.req("DELETE", "/v1/assets/"+a, nil); resp.Code != 202 {
			e.t.Fatalf("delete %s: HTTP %d", a, resp.Code)
		}
	}
	rec := worker.NewReconciler(e.st, e.stor.Storage, slog.Default(), -time.Second, 100)
	if _, err := rec.SweepDeletedAssets(context.Background()); err != nil {
		e.t.Fatalf("purge sweep: %v", err)
	}
	for _, a := range assetIDs {
		if resp := e.req("GET", "/v1/assets/"+a, nil); resp.Code != 404 {
			e.t.Fatalf("precondition: %s should be purged (404), got %d", a, resp.Code)
		}
	}
}

func reasonStr(r *string) string {
	if r == nil {
		return "<nil>"
	}
	return *r
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestE2E_CreateGrant_GoneAssetsDoNotKillTheSet(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	live := e.uploadAndFinalize(harness.SynthImage(t, dir, "live.png", 320, 240), "image/png")
	deleted := e.uploadAndFinalize(harness.SynthImage(t, dir, "deleted.png", 320, 240), "image/png")
	purged := e.uploadAndFinalize(harness.SynthImage(t, dir, "purged.png", 320, 240), "image/png")
	e.deleteAndPurge(purged)
	if resp := e.req("DELETE", "/v1/assets/"+deleted, nil); resp.Code != 202 {
		t.Fatalf("delete: %d", resp.Code)
	}

	code, g, body := e.tryGrant(live, deleted, purged)
	if code != http.StatusCreated {
		t.Fatalf("grant over {live, deleted, purged} = %d %s — one gone asset killed the whole set", code, body)
	}
	if !reflect.DeepEqual(sorted(g.Assets), sorted([]string{live, deleted, purged})) {
		t.Fatalf("grant froze %v, want the full requested set", g.Assets)
	}
	if g.GoneAssets == nil || !reflect.DeepEqual(sorted(*g.GoneAssets), sorted([]string{deleted, purged})) {
		t.Fatalf("gone_assets = %v, want exactly the deleted and purged ids", g.GoneAssets)
	}

	// Through the grant: the live one serves; both gone ones say deleted.
	if res := e.resolveGrant(live, "lightbox", g.ID); res.Delivery == nil {
		t.Fatalf("live asset in the grant refused: %s", reasonStr(res.Reason))
	}
	for _, gone := range []string{deleted, purged} {
		res := e.resolveGrant(gone, "lightbox", g.ID)
		if res.Delivery != nil || res.Reason == nil || *res.Reason != string(plate.ReasonCodeDeleted) {
			t.Fatalf("gone asset %s through the grant = %+v / %s, want reason deleted", gone, res.Delivery, reasonStr(res.Reason))
		}
	}

	// A grant with nothing gone carries no gone_assets at all.
	if _, g2, _ := e.tryGrant(live); g2.GoneAssets != nil {
		t.Fatalf("all-live grant carries gone_assets %v", *g2.GoneAssets)
	}
	// A set naming the same asset twice is not a foreign asset.
	if code, _, body := e.tryGrant(live, live); code != http.StatusCreated {
		t.Fatalf("grant naming one asset twice = %d %s, want 201", code, body)
	}
}

// (c) unchanged: a foreign or never-existing id refuses the whole set, with the
// same body either way and no id named — and a gone own asset beside it does
// not turn the refusal into an oracle.
func TestE2E_CreateGrant_ForeignStillRefusesWholeSet(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()
	own := e.uploadAndFinalize(harness.SynthImage(t, dir, "own.png", 320, 240), "image/png")
	purged := e.uploadAndFinalize(harness.SynthImage(t, dir, "purged.png", 320, 240), "image/png")
	e.deleteAndPurge(purged)

	// Account B's asset (and B's purged asset: gone for B is still foreign for A).
	const b = "grant-b-acct"
	if err := e.st.CreateAccount(ctx, b, "", ""); err != nil {
		t.Fatal(err)
	}
	aTok, aAcct := e.token, e.account
	e.token, e.account = signToken(t, e.priv, b, "assets:read,assets:write,grants:manage"), b
	foreign := e.uploadAndFinalize(harness.SynthImage(t, dir, "b.png", 320, 240), "image/png")
	foreignPurged := e.uploadAndFinalize(harness.SynthImage(t, dir, "bp.png", 320, 240), "image/png")
	e.deleteAndPurge(foreignPurged)
	e.token, e.account = aTok, aAcct

	var bodies []string
	for _, set := range [][]string{
		{own, foreign},
		{own, "01NEVEREXISTED0000000000000"},
		{own, purged, foreign},
		{own, foreignPurged},
	} {
		code, _, body := e.tryGrant(set...)
		if code != http.StatusForbidden {
			t.Fatalf("grant over %v = %d %s, want 403 for the whole set", set, code, body)
		}
		for _, id := range []string{foreign, foreignPurged, b} {
			if strings.Contains(body, id) {
				t.Fatalf("refusal body names %q: %s", id, body)
			}
		}
		bodies = append(bodies, body)
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("foreign vs never-existed refusals differ (an existence oracle): %q vs %q", bodies[0], b)
		}
	}
}

// A grant issued while its assets were live keeps answering honestly after one
// of them is purged: `deleted`, not `unauthorized` (which a caller would retry).
func TestE2E_ExistingGrant_PurgedAssetAnswersDeleted(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	keep := e.uploadAndFinalize(harness.SynthImage(t, dir, "k.png", 320, 240), "image/png")
	doomed := e.uploadAndFinalize(harness.SynthImage(t, dir, "d.png", 320, 240), "image/png")
	grantID := e.createGrant(time.Now().Add(time.Hour), keep, doomed)
	e.deleteAndPurge(doomed)
	time.Sleep(120 * time.Millisecond) // past the e2e grant-cache window

	res := e.resolveGrant(doomed, "lightbox", grantID)
	if res.Delivery != nil || res.Reason == nil || *res.Reason != string(plate.ReasonCodeDeleted) {
		t.Fatalf("purged asset in a live grant = %+v / %s, want reason deleted", res.Delivery, reasonStr(res.Reason))
	}
	if res := e.resolveGrant(keep, "lightbox", grantID); res.Delivery == nil {
		t.Fatalf("the rest of the grant stopped serving: %s", reasonStr(res.Reason))
	}
}

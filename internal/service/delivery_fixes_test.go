package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/store"
)

// Handler-level proofs for the delivery fixes in the security batch. Each drives
// the real router + auth + delivery handlers over a stub store, through surfaces
// that predate the batch, so each FAILS on the pre-batch code.

func resolveBody(t *testing.T, rec *httptest.ResponseRecorder) plate.DeliveryResolution {
	t.Helper()
	raw := trimBody(rec)
	var out plate.DeliveryResolution
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode resolution: %v (%s)", err, raw)
	}
	return out
}

func reasonOf(r plate.DeliveryResolution) string {
	if r.Reason == nil {
		return "<nil>"
	}
	return string(*r.Reason)
}

// ── item 3: the default granted-URL TTL obeys its own cap ───────────────────

// New with no TTL configured must not exceed GrantedImageMaxTTL — the cap was
// only checked against an explicit PLATE_GRANTED_URL_TTL, and the default was 5m.
func TestNew_DefaultGrantedTTLWithinCap(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, 10 * time.Minute, GrantedImageMaxTTL + time.Nanosecond} {
		svc := New(Config{GrantURLTTL: ttl})
		if svc.grantURLTTL <= 0 || svc.grantURLTTL > GrantedImageMaxTTL {
			t.Errorf("New(GrantURLTTL=%v) → effective %v; must be in (0, %v]", ttl, svc.grantURLTTL, GrantedImageMaxTTL)
		}
	}
	if svc := New(Config{}); svc.grantURLTTL != 90*time.Second {
		t.Errorf("default granted-URL TTL = %v, want 90s (matching production's PLATE_GRANTED_URL_TTL)", svc.grantURLTTL)
	}
	if svc := New(Config{GrantURLTTL: 30 * time.Second}); svc.grantURLTTL != 30*time.Second {
		t.Errorf("an explicit in-cap TTL must be kept; got %v", svc.grantURLTTL)
	}
}

// The observable form: a granted image URL minted by a service with NO TTL
// configured carries an imgproxy exp within the cap.
func TestGrantedImage_DefaultExpiryWithinCap(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	st := newStubStore()
	st.put(plate.Asset{Id: "01IMG", Account: "acct", Kind: plate.Image,
		Vault: plate.VaultObject{Key: "vault/acct/01IMG", Width: i32(4000), Height: i32(3000)}})
	st.grants["g1/01IMG"] = store.GrantVerdict{Found: true, Covers: true, Account: "acct"}
	h := stubService(t, st, auth.NewVerifier(pub, "", "")).Router() // stubConfig sets no GrantURLTTL
	before := time.Now()
	rec := do(t, h, "GET", "/v1/assets/01IMG/url?intent=lightbox&grant=g1", stubToken(t, priv, "someone", "assets:read"))
	res := resolveBody(t, rec)
	if res.Delivery == nil {
		t.Fatalf("granted image refused: %s", reasonOf(res))
	}
	i := strings.Index(res.Delivery.Url, "/exp:")
	if i < 0 {
		t.Fatalf("granted image URL has no exp: %s", res.Delivery.Url)
	}
	var exp int64
	if _, err := fmt.Sscan(res.Delivery.Url[i+len("/exp:"):], &exp); err != nil {
		t.Fatalf("parse exp: %v", err)
	}
	if lives := time.Unix(exp, 0).Sub(before); lives > GrantedImageMaxTTL+time.Second {
		t.Fatalf("granted image URL lives %v past issue with no TTL configured; cap is %v", lives.Round(time.Second), GrantedImageMaxTTL)
	}
}

// ── item 4: the owner `original` path refuses once deleted_at is set ─────────

func deletedDoc(st *stubStore) {
	now := time.Now()
	st.put(plate.Asset{Id: "01DOC", Account: "acct", Kind: plate.Document, DeletedAt: &now,
		Vault: plate.VaultObject{Key: "vault/acct/01DOC"}})
}

func TestOwnerOriginal_DeletedAssetRefused(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	st := newStubStore()
	deletedDoc(st)
	h := stubService(t, st, auth.NewVerifier(pub, "", "")).Router()
	rec := do(t, h, "GET", "/v1/assets/01DOC/url?intent=original", stubToken(t, priv, "acct", "assets:read"))
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve original of a deleted asset = %d %s, want 200 + refusal", rec.Code, trimBody(rec))
	}
	res := resolveBody(t, rec)
	if res.Delivery != nil {
		t.Fatalf("a DELETED asset's original still resolves on the owner path: %s", res.Delivery.Url)
	}
	if reasonOf(res) != string(plate.ReasonCodeDeleted) {
		t.Fatalf("reason = %s, want deleted (the same answer every other intent gives)", reasonOf(res))
	}
}

// An original URL minted while the asset was live stops at the download edge
// the moment deleted_at is set — not when its signature expires.
func TestOwnerOriginal_URLMintedBeforeDeleteRefusedAtEdge(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	st := newStubStore()
	st.put(plate.Asset{Id: "01DOC", Account: "acct", Kind: plate.Document, Vault: plate.VaultObject{Key: "vault/acct/01DOC"}})
	cfg := stubConfig(st, auth.NewVerifier(pub, "", ""))
	cfg.Storage = stubStorage{}
	h := New(cfg).Router()

	rec := do(t, h, "GET", "/v1/assets/01DOC/url?intent=original", stubToken(t, priv, "acct", "assets:read"))
	res := resolveBody(t, rec)
	if res.Delivery == nil {
		t.Fatalf("live original refused: %s", reasonOf(res))
	}
	u, _ := url.Parse(res.Delivery.Url)
	edge := u.Path + "?" + u.RawQuery
	if got := do(t, h, "GET", edge, ""); got.Code != http.StatusFound {
		t.Fatalf("precondition: live original download = %d, want 302", got.Code)
	}

	deletedDoc(st) // the owner deletes it
	if got := do(t, h, "GET", edge, ""); got.Code != http.StatusForbidden {
		t.Fatalf("an original URL minted before the delete still downloads after it: %d %s", got.Code, got.Header().Get("Location"))
	}
}

// ── item 5 (PKG-2): granted video × image-ladder intents serve the poster ────

func videoWithPoster(st *stubStore, posterStatus string) {
	st.put(plate.Asset{Id: "01VID", Account: "acct", Kind: plate.Video,
		Vault: plate.VaultObject{Key: "vault/acct/01VID", Width: i32(3840), Height: i32(2160)},
		Renditions: []plate.Rendition{
			{Intent: plate.Poster, Status: plate.RenditionStatus(posterStatus), Width: i32(3840), Height: i32(2160)},
			{Intent: plate.Detail, Status: plate.RenditionStatus("ready")},
		}})
	st.grants["g1/01VID"] = store.GrantVerdict{Found: true, Covers: true, Account: "acct"}
}

func TestGrantedVideo_ImageIntentsServeBoundedPoster(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	st := newStubStore()
	videoWithPoster(st, "ready")
	h := stubService(t, st, auth.NewVerifier(pub, "", "")).Router()
	tok := stubToken(t, priv, "recipient-side", "assets:read")
	grantedConf := loadImgproxyConf(t, grantedImgproxyToml)
	const grantedBase = "https://plate-img-granted.example"
	src := "/plain/s3://plate/delivery/acct/01VID/poster"

	for _, c := range []struct{ intent, device, preset string }{
		{"thumbnail", "mobile", "thumbnail"}, {"thumbnail", "desktop", "thumbnail"},
		{"grid", "mobile", "grid"}, {"grid", "desktop", "grid"},
		{"lightbox", "mobile", "lightbox_mobile"}, {"lightbox", "desktop", "lightbox"},
	} {
		rec := do(t, h, "GET", "/v1/assets/01VID/url?intent="+c.intent+"&device="+c.device+"&grant=g1", tok)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s/%s: HTTP %d %s", c.intent, c.device, rec.Code, trimBody(rec))
		}
		res := resolveBody(t, rec)
		if res.Delivery == nil {
			t.Fatalf("%s/%s: granted video with a ready poster refused: %s", c.intent, c.device, reasonOf(res))
		}
		d := res.Delivery
		if d.Mode != plate.Granted || d.Expires == nil {
			t.Errorf("%s/%s: mode %q expires %v, want granted with an expiry", c.intent, c.device, d.Mode, d.Expires)
		}
		if strings.Contains(d.Url, "/v1/download/") {
			t.Fatalf("%s/%s: granted video image intent signed as a /v1/download of a never-written object (PKG-2): %s", c.intent, c.device, d.Url)
		}
		if !strings.HasPrefix(d.Url, grantedBase+"/") || !strings.Contains(d.Url, "/pr:"+c.preset+"/exp:") || !strings.HasSuffix(d.Url, src) {
			t.Fatalf("%s/%s: want the bounded poster on the granted imgproxy (pr:%s, exp, source = poster rendition); got %s", c.intent, c.device, c.preset, d.Url)
		}
		// Accepted by the committed granted imgproxy config, and dead after exp.
		path := splitSignedImageURL(t, d.Url, grantedBase, []byte("key"), []byte("salt"))
		if err := parseImgproxyPath(grantedConf, path, time.Now()); err != nil {
			t.Errorf("%s/%s: granted poster URL rejected by %s: %v", c.intent, c.device, grantedImgproxyToml, err)
		}
		if err := parseImgproxyPath(grantedConf, path, d.Expires.Add(time.Second)); err == nil {
			t.Errorf("%s/%s: granted poster URL still accepted after its exp", c.intent, c.device)
		}
		// Bounded: the reported output is the ladder's, never the 3840x2160 keyframe.
		if d.Width == nil || d.Height == nil || *d.Width >= 3840 || *d.Height >= 2160 {
			t.Errorf("%s/%s: output dims %v x %v — not bounded by the ladder", c.intent, c.device, d.Width, d.Height)
		}
	}
}

// A pending/not_derived poster gives the same honest answer as the owner path —
// never a signed URL to nothing.
func TestGrantedVideo_PosterNotReadyIsHonest(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	for status, want := range map[string]string{"pending": "pending", "not_derived": "not_derived"} {
		st := newStubStore()
		videoWithPoster(st, status)
		h := stubService(t, st, auth.NewVerifier(pub, "", "")).Router()
		for _, intent := range []string{"thumbnail", "grid", "lightbox"} {
			granted := do(t, h, "GET", "/v1/assets/01VID/url?intent="+intent+"&grant=g1", stubToken(t, priv, "x", "assets:read"))
			owner := do(t, h, "GET", "/v1/assets/01VID/url?intent="+intent, stubToken(t, priv, "acct", "assets:read"))
			g, o := resolveBody(t, granted), resolveBody(t, owner)
			if g.Delivery != nil || reasonOf(g) != want || reasonOf(o) != want {
				t.Errorf("poster %s, %s: granted=%s (delivery %v), owner=%s; want both %s", status, intent, reasonOf(g), g.Delivery != nil, reasonOf(o), want)
			}
		}
	}
}

// ── item 6: a purged asset inside a live grant answers `deleted` ─────────────

func TestGrantedPurgedAsset_AnswersDeleted(t *testing.T) {
	pub, priv := auth.TestKeyPair()
	st := newStubStore()
	// No asset row (the sweep removed it), but the grant covers it and the
	// grant's account owned it.
	st.grants["g1/01GONE"] = store.GrantVerdict{Found: true, Covers: true, Account: "acct"}
	st.purged["acct/01GONE"] = true
	// A covered id that was never the account's (no purge record) stays opaque.
	st.grants["g1/01NEVER"] = store.GrantVerdict{Found: true, Covers: true, Account: "acct"}
	h := stubService(t, st, auth.NewVerifier(pub, "", "")).Router()
	tok := stubToken(t, priv, "x", "assets:read")

	rec := do(t, h, "GET", "/v1/assets/01GONE/url?intent=lightbox&grant=g1", tok)
	if res := resolveBody(t, rec); res.Delivery != nil || reasonOf(res) != string(plate.ReasonCodeDeleted) {
		t.Fatalf("purged asset in a live grant = %s, want reason deleted (so a caller stops retrying)", trimBody(rec))
	}
	rec = do(t, h, "GET", "/v1/assets/01NEVER/url?intent=lightbox&grant=g1", tok)
	if res := resolveBody(t, rec); reasonOf(res) != string(plate.ReasonCodeUnauthorized) {
		t.Fatalf("a covered id with no purge record = %s, want unauthorized", trimBody(rec))
	}
	// An uncovered id never reaches the purge check, purged or not.
	st.purged["acct/01OTHER"] = true
	rec = do(t, h, "GET", "/v1/assets/01OTHER/url?intent=lightbox&grant=g1", tok)
	if res := resolveBody(t, rec); reasonOf(res) != string(plate.ReasonCodeUnauthorized) {
		t.Fatalf("an id the grant does not cover = %s, want unauthorized (no oracle)", trimBody(rec))
	}
}

package plate_test

// Incident (spec §7): "a vault object exposes no delivery URL, at any intent but
// `original`."
//
// The dated failure (spec §1, §3.1, 2026-07-14): the lightbox served
// `tr:orig-true` — the raw original. A phone decoded 292MB in one bitmap, the
// page peaked at 516MB, the tab died. Plate's structural fix: a vault object and
// a rendition are DIFFERENT TYPES. The vault object has no URL field AT ALL — not
// a URL you are told not to use. Asking for a vault object's delivery URL is a
// type error, not a policy violation. The only route to raw bytes is
// `intent=original`, which must be named.
//
// This test has two halves, both structural:
//   1. Reflect over the generated VaultObject type and assert it has NO field
//      that is a delivery URL. This checks the CONTRACT's own invariant against
//      the real generated Go — the absence is the design (spec §3.1).
//   2. For every non-`original` intent, the resolved delivery must not be the
//      vault key / raw original; only `original` yields the authenticated
//      download.

import (
	"reflect"
	"strings"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/support"
)

// The vault object carries a storage `key` (server-to-server, never handed to a
// browser) and probed metadata. It must carry nothing that is, or reads as, a
// browser-reachable delivery URL.
func TestVaultObject_HasNoDeliveryURLField(t *testing.T) {
	typ := reflect.TypeOf(plate.VaultObject{})

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.ToLower(f.Name)
		jsonTag := strings.ToLower(strings.Split(f.Tag.Get("json"), ",")[0])

		// A delivery URL would surface as a field named/ tagged url, href, src,
		// delivery, or cdn. `key` is explicitly allowed (it is the storage key,
		// documented server-to-server only) and is NOT a delivery URL.
		for _, forbidden := range []string{"url", "href", "src", "cdn", "delivery"} {
			if name == forbidden || jsonTag == forbidden {
				t.Errorf("VaultObject has a %q field (%s) — the vault object must have NO delivery URL field at all; the absence is the design (spec §3.1). This is the structural version of 'never hand media.url to an <img>'.", forbidden, f.Name)
			}
		}
	}
}

// Delivery-by-intent: only `original` returns the raw-bytes route. Every other
// intent must resolve to a rendition URL, never the vault original. The resolver
// stub encodes this rule; the assertion checks the RESOLVED url, not that a
// guard function ran.
func TestResolveByIntent_OnlyOriginalReachesRawBytes(t *testing.T) {
	vaultKey := "uri/01J9Z0K3Q4XR7NB8YF2WV6TCEH" // the {account}/{asset-id} storage key
	r := support.NewIntentResolver(vaultKey)

	nonOriginal := []plate.Intent{
		plate.Thumbnail, plate.Grid, plate.Lightbox,
		plate.Poster, plate.Loop, plate.Detail,
	}
	for _, intent := range nonOriginal {
		res := r.Resolve(intent)
		if res.Delivery == nil {
			// A refusal (e.g. pending) is fine — it is certainly not the raw
			// original. What must never happen is a delivery URL that IS the vault
			// original.
			continue
		}
		if support.IsRawOriginalURL(res.Delivery.Url, vaultKey) {
			t.Errorf("intent %q resolved to the RAW ORIGINAL (%q) — this is the 2026-07-14 tab-killer (the lightbox served tr:orig-true). Only intent=original may reach raw bytes.", intent, res.Delivery.Url)
		}
	}

	// `original` is the one deliberate escape hatch: it MUST resolve, and to an
	// authenticated, expiring download URL — never a stable CDN URL (spec §4.1).
	orig := r.Resolve(plate.Original)
	if orig.Delivery == nil {
		t.Fatal("intent=original did not resolve; it is the explicit, named route to raw bytes and must work")
	}
	if orig.Delivery.Expires == nil {
		t.Error("intent=original returned a URL with no expiry — the raw-bytes route must be short-lived and authenticated, never a stable/embeddable URL (spec §4.1)")
	}
	if orig.Delivery.Mode != plate.Signed && orig.Delivery.Mode != plate.Granted {
		t.Errorf("intent=original resolved with mode %q — raw bytes must be signed/granted, never public/CDN-cached", orig.Delivery.Mode)
	}
}

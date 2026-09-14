package plate_test

// Incident (spec §7): "a new media type added without an allowlist entry FAILS,
// loudly."
//
// This is the generalisation of the document/AV incidents (spec §1): the CDN
// bypass is an ALLOWLIST, and the failure mode is a NEW kind silently opting IN
// to the metered CDN — no error, only a bill. The fix Plate encodes is that
// routing is a TOTAL function over closed enums that ERRORS on anything
// unmapped, rather than a default branch that quietly picks the metered path.
//
// V2.1 widened routing from `kind` to `(kind, intent)`, because a video's host
// now depends on the intent: its image intents serve a bounded poster through
// the image engine, its A/V intents stay on R2. So exhaustiveness is over the
// CROSS PRODUCT, and every pair must be a decision someone made.
//
// These drive the REAL table in internal/service. They previously drove a
// reference stub in test/support — a duplicate that could (and did) diverge from
// production, which would have let the very drift this test exists to catch pass
// unnoticed. The stub is gone.

import (
	"errors"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/service"
)

func TestUnmappedMediaKind_FailsLoudly_NotSilentDefault(t *testing.T) {
	// A kind that is NOT in the allowlist. This stands for "a new mediaType added
	// to the system without an allowlist entry."
	unlisted := plate.MediaKind("hologram")

	host, err := service.RouteDelivery(unlisted, plate.Thumbnail)
	if err == nil {
		t.Fatalf("an unlisted media kind routed to %v with NO error — this is the silent fall-through that sent a PDF to the metered CDN (spec §1). It must fail loudly.", host)
	}
	var unroutable service.ErrUnroutableKind
	if !errors.As(err, &unroutable) {
		t.Fatalf("wrong error type for an unlisted kind: %v", err)
	}
}

// An unmapped INTENT on a known kind must also fail closed, not fall through.
func TestUnmappedIntent_OnKnownKind_FailsLoudly(t *testing.T) {
	host, err := service.RouteDelivery(plate.Image, plate.Intent("telepathy"))
	if err == nil {
		t.Fatalf("an unlisted intent routed to %v with NO error — an unmapped pair must refuse, never default", host)
	}
	var unroutable service.ErrUnroutableKind
	if !errors.As(err, &unroutable) {
		t.Fatalf("wrong error type for an unlisted intent: %v", err)
	}
}

// Exhaustiveness over the CROSS PRODUCT. Every (kind, intent) pair the contract
// can express must be a DECISION: either it routes to a named host, or it is
// deliberately unmapped and refuses. What must never happen is a pair nobody
// considered quietly resolving to the metered path.
//
// If the contract adds a kind or an intent, the corresponding Known… list grows
// and every new pair shows up here — the "same change" discipline made
// mechanical.
func TestRoutingTable_ExhaustiveOverContractEnums(t *testing.T) {
	kinds := service.KnownMediaKinds()
	intents := service.KnownIntents()

	// Sanity: the lists the router iterates must be the contract's actual enum
	// members. A generated member missing from either list is caught here.
	for _, k := range kinds {
		if !k.Valid() {
			t.Errorf("KnownMediaKinds lists %q, which is not a valid contract MediaKind", k)
		}
	}
	for _, i := range intents {
		if !i.Valid() {
			t.Errorf("KnownIntents lists %q, which is not a valid contract Intent", i)
		}
	}

	// Every kind must have at least one route — an entirely unrouted kind is the
	// original incident.
	for _, k := range kinds {
		if !service.KindHasAnyRoute(k) {
			t.Errorf("contract media kind %q has NO routing entry at all: a new kind must be routed in the same change that adds it", k)
		}
	}

	// The cross product: each pair either routes to a real host or refuses. The
	// assertion is that nothing resolves to the metered host by accident — a pair
	// that routes to HostImageCDN must be one of the deliberate image-transform
	// cases, i.e. the asset being transformed is genuinely a still image.
	for _, k := range kinds {
		for _, i := range intents {
			host, err := service.RouteDelivery(k, i)
			if err != nil {
				continue // deliberately unmapped → refuses. That is a decision.
			}
			if host != service.HostImageCDN {
				continue
			}
			// Routed to the METERED engine. Only two things may: an image (its
			// vault original), or a video's image intents (its poster rendition,
			// a still JPEG). Anything else is the 528-VPU / PDF class of bug.
			switch {
			case k == plate.Image:
			case k == plate.Video && (i == plate.Thumbnail || i == plate.Grid || i == plate.Lightbox):
			default:
				t.Errorf("(%s, %s) routes to the METERED image CDN. Only an image, or a video's thumbnail/grid/lightbox (which serve its still poster), may transform there — this is how a PDF reached ik.imagekit.io and how AV hit 528 VPUs.", k, i)
			}
		}
	}

	// Tripwires so enum growth is visible even before a new member is first used.
	const contractMediaKindCount = 4 // image, video, audio, document (spec §3)
	if len(kinds) != contractMediaKindCount {
		t.Fatalf("KnownMediaKinds has %d entries, expected %d — if the contract added a MediaKind, route every (kind, intent) pair AND update this tripwire in the same change", len(kinds), contractMediaKindCount)
	}
	const contractIntentCount = 10 // thumbnail, grid, lightbox, zoom_1..3, poster, loop, detail, original
	if len(intents) != contractIntentCount {
		t.Fatalf("KnownIntents has %d entries, expected %d — if the contract added an Intent, decide its route for EVERY kind AND update this tripwire in the same change", len(intents), contractIntentCount)
	}
}

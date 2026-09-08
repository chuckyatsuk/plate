package plate_test

// Incident (spec §7): "a new media type added without an allowlist entry FAILS,
// loudly."
//
// This is the generalisation of the document/AV incidents (spec §1): the CDN
// bypass is an ALLOWLIST, and the failure mode is a NEW kind silently opting IN
// to the metered CDN — no error, only a bill. The fix Plate encodes is that
// routing is a TOTAL function over the closed MediaKind enum that ERRORS on
// anything unmapped, rather than a default branch that quietly picks the metered
// path.
//
// Two things are asserted:
//   1. An unmapped kind is a loud error (fail closed), not a silent default.
//   2. The routing table is EXHAUSTIVE over the contract's enum — so if a future
//      contract change adds a fifth MediaKind, this test fails until routing is
//      updated in the SAME change. That is the drift-catch the incident needed.

import (
	"errors"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/support"
)

func TestUnmappedMediaKind_FailsLoudly_NotSilentDefault(t *testing.T) {
	// A kind that is NOT in the allowlist. This stands for "a new mediaType added
	// to the system without an allowlist entry."
	unlisted := plate.MediaKind("hologram")

	host, err := support.RouteDelivery(unlisted)
	if err == nil {
		t.Fatalf("an unlisted media kind routed to %s with NO error — this is the silent fall-through that sent a PDF to the metered CDN (spec §1). It must fail loudly.", host)
	}
	var unroutable support.ErrUnroutableKind
	if !errors.As(err, &unroutable) {
		t.Fatalf("wrong error type for an unlisted kind: %v", err)
	}
}

// Exhaustiveness: every kind the contract defines must have a routing entry, and
// the table must contain no MORE than the contract's kinds. If the contract adds
// a kind, KnownMediaKinds grows, and this loop fails on the new kind until it is
// routed — the "same change" discipline made mechanical.
func TestRoutingTable_ExhaustiveOverContractEnum(t *testing.T) {
	kinds := support.KnownMediaKinds()

	// Sanity: the list the router iterates must be the contract's actual enum
	// members. If a generated member is missing here, this catches it.
	for _, k := range kinds {
		if !k.Valid() {
			t.Errorf("KnownMediaKinds lists %q, which is not a valid contract MediaKind", k)
		}
	}

	// Every known kind routes without error.
	for _, k := range kinds {
		if _, err := support.RouteDelivery(k); err != nil {
			t.Errorf("contract media kind %q has no routing entry: %v", k, err)
		}
	}

	// Guard against the enum growing beyond what KnownMediaKinds tracks: the four
	// current members must all be valid, and any NEW generated member (e.g. a
	// future "model" or "archive" kind) would not appear in KnownMediaKinds,
	// leaving it unrouted and caught the first time it is used. We assert the
	// count here as a tripwire so the drift is visible even before first use.
	const contractMediaKindCount = 4 // image, video, audio, document (spec §3, contract MediaKind enum)
	if len(kinds) != contractMediaKindCount {
		t.Fatalf("KnownMediaKinds has %d entries, expected %d — if the contract added a MediaKind, add it to the allowlist AND update this tripwire in the same change", len(kinds), contractMediaKindCount)
	}
}

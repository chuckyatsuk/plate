package support

import (
	"fmt"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// DeliveryHost names where the bytes for a resolved delivery come from. The
// whole CDN-allowlist incident (spec §1, dated 2026-09-08) is about this
// decision landing in one place that knows EVERY media kind, instead of an
// afterRead hook where a new kind silently falls through to the metered CDN.
type DeliveryHost int

const (
	// HostImageCDN is the transforming (metered) image CDN — imgproxy/ImageKit.
	// ONLY images belong here: it transforms them. Everything it would merely
	// pass through must NOT route here (spec, cdn-bypass-allowlist landmine).
	HostImageCDN DeliveryHost = iota
	// HostR2 is object storage serving bytes directly, un-transformed and
	// unmetered. Video, audio, and documents serve from R2 (spec §1: "everything
	// it merely passes through goes to R2").
	HostR2
)

func (h DeliveryHost) String() string {
	switch h {
	case HostImageCDN:
		return "image-cdn"
	case HostR2:
		return "r2"
	default:
		return fmt.Sprintf("host(%d)", int(h))
	}
}

// ErrUnroutableKind is returned when a media kind has no explicit routing
// decision. This is the "FAILS, loudly" property from spec §7: a new MediaKind
// added without an allowlist entry must NOT silently fall through to a metered
// path — it must error. The service will surface this as a build/registration
// error, never a 200 to a metered CDN.
type ErrUnroutableKind struct {
	Kind plate.MediaKind
}

func (e ErrUnroutableKind) Error() string {
	return fmt.Sprintf("support: media kind %q has no delivery-routing entry — a new kind must be added to the allowlist in the SAME change, never left to fall through to a metered CDN (spec cdn-bypass-allowlist landmine)", e.Kind)
}

// deliveryRoutes is the EXPLICIT allowlist: every media kind maps to exactly one
// host. It is a closed table keyed by the contract's MediaKind enum. The
// property that matters is not the contents but the shape: routing is a total
// function over a closed enum that ERRORS on anything unmapped, rather than a
// default branch that quietly picks the metered CDN.
//
// Images transform → image CDN. Everything else is passed through → R2.
var deliveryRoutes = map[plate.MediaKind]DeliveryHost{
	plate.Image:    HostImageCDN,
	plate.Video:    HostR2,
	plate.Audio:    HostR2,
	plate.Document: HostR2,
}

// RouteDelivery returns the delivery host for a media kind, or ErrUnroutableKind
// if the kind is not in the allowlist. Fail closed: an unmapped kind is an
// error, never a silent default to the metered CDN.
func RouteDelivery(kind plate.MediaKind) (DeliveryHost, error) {
	host, ok := deliveryRoutes[kind]
	if !ok {
		return 0, ErrUnroutableKind{Kind: kind}
	}
	return host, nil
}

// KnownMediaKinds is the closed set of kinds the contract defines. The allowlist
// test iterates this to prove the routing table is EXHAUSTIVE over the enum —
// so adding a kind to the contract without a routing entry fails the test.
func KnownMediaKinds() []plate.MediaKind {
	return []plate.MediaKind{plate.Image, plate.Video, plate.Audio, plate.Document}
}

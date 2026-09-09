package service

import (
	"fmt"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// This file is the read-path delivery logic: intent → URL, with the routing
// decision (spec §1, the CDN-allowlist landmine) in ONE place that knows every
// media kind. It constructs URL STRINGS only — Plate serves URLs, never bytes
// (spec Q5) — so Phase 1 never contacts imgproxy or R2 at delivery time.
//
// The routing table is a total function over the closed MediaKind enum that
// ERRORS on anything unmapped, rather than a default branch that quietly picks
// the metered CDN. A new media kind added to the contract without a routing
// entry fails loudly — the exact property the allowlist_exhaustive test asserts.

// DeliveryHost names where a resolved delivery's bytes come from.
type DeliveryHost int

const (
	// HostImageCDN is the transforming (metered) image engine — imgproxy. ONLY
	// images belong here: it transforms them. Anything it would merely pass
	// through must NOT route here (the cdn-bypass-allowlist landmine).
	HostImageCDN DeliveryHost = iota
	// HostR2 serves bytes directly, un-transformed and unmetered: video, audio,
	// documents, and the authenticated `original` download.
	HostR2
)

// ErrUnroutableKind is returned when a media kind has no explicit routing entry.
// This is the "FAILS, loudly" property: a new MediaKind must be added to the
// allowlist in the same change, never left to fall through to a metered path.
type ErrUnroutableKind struct{ Kind plate.MediaKind }

func (e ErrUnroutableKind) Error() string {
	return fmt.Sprintf("service: media kind %q has no delivery-routing entry — add it to the allowlist in the SAME change, never fall through to a metered CDN", e.Kind)
}

// deliveryRoutes is the EXPLICIT allowlist. Images transform → image CDN.
// Everything else passes through → R2. Closed table keyed by the contract enum.
var deliveryRoutes = map[plate.MediaKind]DeliveryHost{
	plate.Image:    HostImageCDN,
	plate.Video:    HostR2,
	plate.Audio:    HostR2,
	plate.Document: HostR2,
}

// RouteDelivery returns the delivery host for a media kind, or ErrUnroutableKind.
// Fail closed: an unmapped kind is an error, never a silent default.
func RouteDelivery(kind plate.MediaKind) (DeliveryHost, error) {
	host, ok := deliveryRoutes[kind]
	if !ok {
		return 0, ErrUnroutableKind{Kind: kind}
	}
	return host, nil
}

// URLBuilder constructs delivery URL strings for each host. Injected so no live
// imgproxy/R2 is contacted in Phase 1 and so the strings are unit-testable.
type URLBuilder struct {
	// ImageCDNBase is the imgproxy delivery base, e.g. https://cdn.example.
	ImageCDNBase string
	// R2PublicBase is the R2 public base for pass-through bytes.
	R2PublicBase string
	// DownloadBase is the authenticated download endpoint base for `original`.
	DownloadBase string
}

// Resolve turns an intent into a DeliveryResolution for an asset of the given
// kind, whose vault original lives at vaultKey. It enforces the one rule the
// vault/delivery wall depends on: only intent=original reaches raw bytes, via a
// short-lived authenticated download URL — never a stable CDN/storage path
// (spec §3.1, §4.1). Every other intent resolves to a bounded rendition URL on
// the appropriate host per the allowlist.
func (b URLBuilder) Resolve(intent plate.Intent, kind plate.MediaKind, vaultKey string) (plate.DeliveryResolution, error) {
	host, err := RouteDelivery(kind)
	if err != nil {
		// Fail loud, not to a metered CDN. The handler renders this as a 500-class
		// error, never a 200 URL.
		return plate.DeliveryResolution{}, err
	}

	// `original` is intentionally NOT handled here. It is the owner's
	// authenticated escape hatch and is now minted as a real HMAC-signed
	// /v1/download URL in the service handler (handleResolveDeliveryURL), which
	// holds the signer; URLBuilder only builds unsigned public-shape URLs. Calling
	// Resolve with original is a programming error — guard it so a stray caller
	// fails loud instead of silently producing an unsigned raw-bytes path.
	if intent == plate.Original {
		return plate.DeliveryResolution{}, fmt.Errorf("service: URLBuilder.Resolve must not be called with intent=original — it is signed in the handler")
	}

	// A non-original intent resolves to a bounded rendition URL on the host the
	// allowlist chose — never the vault original.
	switch host {
	case HostImageCDN:
		// Images transform on the fly: imgproxy fetches the vault original and
		// applies the intent's preset. The URL names the PRESET (a purpose), never
		// ad-hoc params (spec §4.1); ONLY_PRESETS enforces that at imgproxy.
		return plate.DeliveryResolution{
			Intent: intent,
			Delivery: &plate.Delivery{
				Url:  fmt.Sprintf("%s/%s/plain/%s", b.ImageCDNBase, intent, vaultKey),
				Mode: plate.Public,
			},
		}, nil
	default: // HostR2 — A/V renditions serve the worker-written object DIRECTLY.
		// The URL MUST point at the exact key the worker wrote (id.RenditionKey),
		// not a fabricated path — otherwise a ready rendition 404s (the deployed-
		// smoke bug). Shared key function keeps write and read in lockstep.
		return plate.DeliveryResolution{
			Intent: intent,
			Delivery: &plate.Delivery{
				Url:  b.R2PublicBase + "/" + id.RenditionKey(vaultKey, string(intent)),
				Mode: plate.Public,
			},
		}, nil
	}
}

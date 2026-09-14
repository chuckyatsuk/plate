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

// ErrUnroutableKind is returned when a (kind, intent) pair has no explicit
// routing entry. This is the "FAILS, loudly" property: a new MediaKind or Intent
// must be added to the allowlist in the same change, never left to fall through
// to a metered path. Intent is zero-valued when a whole kind is unmapped.
type ErrUnroutableKind struct {
	Kind   plate.MediaKind
	Intent plate.Intent
}

func (e ErrUnroutableKind) Error() string {
	if e.Intent == "" {
		return fmt.Sprintf("service: media kind %q has no delivery-routing entry — add it to the allowlist in the SAME change, never fall through to a metered CDN", e.Kind)
	}
	return fmt.Sprintf("service: (%q, %q) has no delivery-routing entry — add the pair to the allowlist in the SAME change, never fall through to a metered CDN", e.Kind, e.Intent)
}

// routeKey is one cell of the allowlist. Routing is keyed on the PAIR because a
// video's host depends on the intent: its image intents serve the bounded
// poster through the image engine, while its A/V intents are raw public bytes.
type routeKey struct {
	kind   plate.MediaKind
	intent plate.Intent
}

// deliveryRoutes is the EXPLICIT allowlist, keyed by (kind, intent).
//
// The property that matters is the SHAPE, not the contents: a total function
// over closed enums that ERRORS on an unmapped pair, rather than a default
// branch that quietly picks the metered CDN. That is the cdn-bypass-allowlist
// landmine (spec §1, §7) — a PDF reaching the image CDN cost real money and
// produced no error, only a bill.
//
// Widened from kind-only in V2.1, because a VIDEO now has two hosts:
//   - thumbnail/grid/lightbox → the image CDN, serving its POSTER rendition
//     through the bounded ladder (a full-resolution keyframe handed straight to
//     a grid tile is the unbounded decode the memory budget exists to prevent).
//   - poster/loop/detail      → public R2, as A/V bytes always have been. The
//     metered engine must never see them.
//   - zoom_*                  → deliberately ABSENT, so they refuse: a deep-zoom
//     ladder over a video still is not something Plate offers.
//
// An entry here is a claim that this pair is SAFE on that host. Adding a kind or
// an intent without deciding every pair fails the exhaustive test.
var deliveryRoutes = map[routeKey]DeliveryHost{}

// imageLadderIntents are the bounded image renditions. For an IMAGE they
// transform the vault original; for a VIDEO they transform its poster rendition.
var imageLadderIntents = []plate.Intent{plate.Thumbnail, plate.Grid, plate.Lightbox}

// zoomIntents are image-only deep-zoom rungs (Phase 3 A2).
var zoomIntents = []plate.Intent{plate.Zoom1, plate.Zoom2, plate.Zoom3}

// avIntents are the transcoded A/V renditions — always raw public bytes.
var avIntents = []plate.Intent{plate.Poster, plate.Loop, plate.Detail}

func init() {
	// IMAGE: the whole image ladder + zoom rungs transform through the engine.
	for _, i := range append(append([]plate.Intent{}, imageLadderIntents...), zoomIntents...) {
		deliveryRoutes[routeKey{plate.Image, i}] = HostImageCDN
	}
	// VIDEO: image intents serve the bounded POSTER through the engine; the A/V
	// renditions stay on R2. Zoom is intentionally unmapped (refuses).
	for _, i := range imageLadderIntents {
		deliveryRoutes[routeKey{plate.Video, i}] = HostImageCDN
	}
	for _, i := range avIntents {
		deliveryRoutes[routeKey{plate.Video, i}] = HostR2
	}
	// AUDIO: `detail` is the transcode; a cover is an AUTHORED image asset in the
	// caller's model, never derived here, so audio has no image-ladder route.
	deliveryRoutes[routeKey{plate.Audio, plate.Detail}] = HostR2
	// DOCUMENT: passed through whole; no derivation, no transform.
	deliveryRoutes[routeKey{plate.Document, plate.Original}] = HostR2
	// `original` is the authenticated download for every kind — never the CDN.
	for _, k := range []plate.MediaKind{plate.Image, plate.Video, plate.Audio, plate.Document} {
		deliveryRoutes[routeKey{k, plate.Original}] = HostR2
	}
}

// KnownMediaKinds is the closed set of kinds the contract defines, and
// KnownIntents the closed set of intents. The exhaustive test iterates their
// CROSS PRODUCT against the table above, so adding either to the contract
// without deciding every pair fails loudly in the same change.
func KnownMediaKinds() []plate.MediaKind {
	return []plate.MediaKind{plate.Image, plate.Video, plate.Audio, plate.Document}
}

func KnownIntents() []plate.Intent {
	return []plate.Intent{
		plate.Thumbnail, plate.Grid, plate.Lightbox,
		plate.Zoom1, plate.Zoom2, plate.Zoom3,
		plate.Poster, plate.Loop, plate.Detail,
		plate.Original,
	}
}

// KindHasAnyRoute reports whether a kind is in the allowlist at all. An entirely
// unmapped kind is the original incident (a new media type silently reaching the
// metered CDN); an unmapped PAIR on a known kind is the narrower refusal.
func KindHasAnyRoute(kind plate.MediaKind) bool {
	for k := range deliveryRoutes {
		if k.kind == kind {
			return true
		}
	}
	return false
}

// RouteDelivery returns the delivery host for a (kind, intent) pair, or
// ErrUnroutableKind. Fail closed: an unmapped pair is an error, never a silent
// default to the metered path.
func RouteDelivery(kind plate.MediaKind, intent plate.Intent) (DeliveryHost, error) {
	host, ok := deliveryRoutes[routeKey{kind, intent}]
	if !ok {
		// Distinguish "this kind is entirely unknown" (the original incident —
		// a new media type with no allowlist entry) from "this pair is not
		// offered" (e.g. zoom on a video), so the error text points at the right
		// fix. Both fail closed.
		if KindHasAnyRoute(kind) {
			return 0, ErrUnroutableKind{Kind: kind, Intent: intent}
		}
		return 0, ErrUnroutableKind{Kind: kind}
	}
	return host, nil
}

// URLBuilder constructs delivery URL strings for each host. Injected so no live
// imgproxy/R2 is contacted in Phase 1 and so the strings are unit-testable.
type URLBuilder struct {
	// ImageCDNBase is the imgproxy delivery base, e.g. https://cdn.example.
	ImageCDNBase string
	// ImageSourceBucket is the R2 bucket imgproxy reads originals from, as a
	// PRIVATE S3 source: imgproxy fetches s3://{bucket}/{vaultKey} with its own R2
	// credentials, never over the public delivery base — so the vault original is
	// never publicly reachable (the wall, spec §3.1/Q5). Empty ⇒ image delivery
	// cannot build a source and is refused.
	ImageSourceBucket string
	// R2PublicBase is the R2 public base for pass-through bytes (A/V renditions,
	// which live under the public `delivery/` prefix).
	R2PublicBase string
	// DownloadBase is the authenticated download endpoint base for `original`.
	DownloadBase string
}

// imgproxySource builds the private S3 source URL imgproxy fetches an original
// from: `s3://{bucket}/{vaultKey}`. Requires IMGPROXY_USE_S3 on the imgproxy side
// with R2 credentials. Returns "" if no bucket is configured.
func (b URLBuilder) imgproxySource(vaultKey string) string {
	if b.ImageSourceBucket == "" {
		return ""
	}
	return "s3://" + b.ImageSourceBucket + "/" + vaultKey
}

// Resolve turns an intent into a DeliveryResolution for an asset of the given
// kind, whose vault original lives at vaultKey. It enforces the one rule the
// vault/delivery wall depends on: only intent=original reaches raw bytes, via a
// short-lived authenticated download URL — never a stable CDN/storage path
// (spec §3.1, §4.1). Every other intent resolves to a bounded rendition URL on
// the appropriate host per the allowlist.
func (b URLBuilder) Resolve(intent plate.Intent, kind plate.MediaKind, vaultKey string) (plate.DeliveryResolution, error) {
	host, err := RouteDelivery(kind, intent)
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
		// Images are NOT built here anymore: every image URL is imgproxy-SIGNED
		// (public included, because imgproxy checks all URLs once keyed) and signing
		// lives on the Service, which holds the signer. The Service resolves images
		// directly (resolveNonOriginal → signedImageURL) and never routes them
		// through URLBuilder. Reaching here with an image is a programming error —
		// fail loud rather than emit an unsigned URL.
		return plate.DeliveryResolution{}, fmt.Errorf("service: URLBuilder.Resolve must not build image URLs — they are imgproxy-signed in the handler")
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

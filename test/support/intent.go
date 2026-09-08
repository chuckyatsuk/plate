package support

import (
	"strings"
	"time"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// IntentResolver maps a purpose to a delivery, enforcing the one rule that
// matters for the vault/delivery wall: only intent=original reaches raw bytes,
// and it does so via a short-lived authenticated download URL — never a stable
// CDN URL (spec §4.1). The service will implement this over real rendition
// state; the stub encodes the routing invariant so the test can assert on the
// resolved URL.
type IntentResolver interface {
	Resolve(intent plate.Intent) plate.DeliveryResolution
}

type intentResolver struct {
	vaultKey string
}

// NewIntentResolver builds a resolver for an asset whose vault original lives at
// vaultKey (the {account}/{asset-id} storage key).
func NewIntentResolver(vaultKey string) IntentResolver {
	return intentResolver{vaultKey: vaultKey}
}

func (r intentResolver) Resolve(intent plate.Intent) plate.DeliveryResolution {
	if intent == plate.Original {
		// The named escape hatch: an authenticated, expiring download URL that is
		// NOT the raw CDN/storage path. Distinct from the vault key.
		exp := time.Now().Add(5 * time.Minute)
		return plate.DeliveryResolution{
			Intent: plate.Original,
			Delivery: &plate.Delivery{
				// A signed download endpoint, not the vault storage key itself.
				Url:     "https://plate.example/v1/download/" + r.vaultKey + "?sig=…",
				Mode:    plate.Signed,
				Expires: &exp,
			},
		}
	}

	// Every other intent resolves to a bounded rendition URL on the delivery CDN
	// — never the vault original.
	return plate.DeliveryResolution{
		Intent: intent,
		Delivery: &plate.Delivery{
			Url:  "https://cdn.example/rendition/" + string(intent) + "/asset.jpg",
			Mode: plate.Public,
		},
	}
}

// IsRawOriginalURL reports whether a delivery URL is (or embeds) the raw vault
// original — the thing that must NEVER be handed to a browser for a non-original
// intent (spec §3.1). It flags both the storage key appearing in a
// browser-facing URL and the ImageKit `tr:orig-true` marker that was the literal
// 2026-07-14 incident.
func IsRawOriginalURL(url, vaultKey string) bool {
	if strings.Contains(url, "tr:orig-true") {
		return true
	}
	// The vault key on a CDN/public path (as opposed to the authenticated
	// download endpoint) means the raw original is browser-reachable.
	if strings.Contains(url, "cdn.example/"+vaultKey) {
		return true
	}
	if strings.Contains(url, "/orig/") || strings.HasSuffix(url, "@orig") {
		return true
	}
	return false
}

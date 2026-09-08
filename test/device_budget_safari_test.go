package plate_test

// Incident (spec §7): "deviceMemory absent (Safari) + small viewport → mobile
// budget."
//
// Behind it (spec §4.2): `navigator.deviceMemory` is Chromium-only and ABSENT on
// Safari — which is the browser that actually dies (iOS Safari counts decoded
// pixels per tab). A clamp that gates the mobile budget on deviceMemory being
// present would give Safari the DESKTOP budget and kill the tab. So a small
// viewport ALONE must be sufficient to take the mobile budget, and the default
// when unspecified is mobile — fail toward the safe budget.
//
// NOTE ON THE HOUSE RULE: this is the one §7 case with no rendered artifact to
// inspect — device-class selection is an input-parsing DECISION made from client
// hints, not a produced file. So this is an honest table test of that decision,
// deliberately, not a "was the clamp function called" assertion. The clamp's
// EFFECT on real pixels is verified against the real engine in
// image_decoded_memory_test.go; here we verify the class chosen from the inputs.

import (
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/support"
)

func TestResolveDeviceClass(t *testing.T) {
	cases := []struct {
		name  string
		hints support.ClientHints
		want  plate.DeviceClass
	}{
		{
			// THE incident: Safari (no deviceMemory) on a phone-width viewport.
			name:  "safari_no_devicememory_small_viewport",
			hints: support.ClientHints{DeviceMemoryPresent: false, ViewportWidth: 390},
			want:  plate.Mobile,
		},
		{
			// Safari on a wide viewport (desktop Safari) — deviceMemory still
			// absent, but the viewport is roomy, so desktop is allowed.
			name:  "safari_no_devicememory_wide_viewport",
			hints: support.ClientHints{DeviceMemoryPresent: false, ViewportWidth: 1680},
			want:  plate.Desktop,
		},
		{
			// Nothing known at all → fail safe to mobile (default is mobile).
			name:  "nothing_known_defaults_mobile",
			hints: support.ClientHints{},
			want:  plate.Mobile,
		},
		{
			// Explicit param always wins, even against a conflicting viewport.
			name:  "explicit_mobile_param_wins",
			hints: support.ClientHints{DeviceParam: "mobile", ViewportWidth: 1920},
			want:  plate.Mobile,
		},
		{
			name:  "explicit_desktop_param_wins",
			hints: support.ClientHints{DeviceParam: "desktop", ViewportWidth: 320},
			want:  plate.Desktop,
		},
		{
			// Chromium reporting low memory → mobile even on a wider viewport.
			name:  "chromium_low_memory_small_viewport_mobile",
			hints: support.ClientHints{DeviceMemoryPresent: true, DeviceMemoryGiB: 2, ViewportWidth: 400},
			want:  plate.Mobile,
		},
		{
			// Roomy Chromium desktop.
			name:  "chromium_high_memory_wide_viewport_desktop",
			hints: support.ClientHints{DeviceMemoryPresent: true, DeviceMemoryGiB: 8, ViewportWidth: 1440},
			want:  plate.Desktop,
		},
		{
			// Exactly at the small-viewport threshold counts as small (mobile).
			name:  "threshold_viewport_is_mobile",
			hints: support.ClientHints{ViewportWidth: 768},
			want:  plate.Mobile,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := support.ResolveDeviceClass(tc.hints)
			if got != tc.want {
				t.Fatalf("ResolveDeviceClass(%+v) = %q, want %q", tc.hints, got, tc.want)
			}
		})
	}
}

// The class must map to the right decoded budget, and — the safety property —
// the default/unknown path must never yield the LARGER budget. A regression that
// flips the default to desktop is exactly what kills a Safari tab.
func TestDefaultBudgetIsTheSafeOne(t *testing.T) {
	def := support.ResolveDeviceClass(support.ClientHints{})
	if support.DecodedBudgetFor(def) != support.MobileDecodedBudget {
		t.Fatalf("default device budget is %d, want the mobile (safe) budget %d — failing toward the larger budget kills the tab it was meant to protect",
			support.DecodedBudgetFor(def), support.MobileDecodedBudget)
	}
	if support.MobileDecodedBudget >= support.DesktopDecodedBudget {
		t.Fatal("mobile budget is not smaller than desktop; the safe budget must be the smaller one")
	}
}

package support

import plate "github.com/chuckyatsuk/plate/internal/plate"

// Decoded-memory budgets in bytes (spec §4.2, §5.4). RGBA = width × height × 4;
// a rendition is bounded so its decoded footprint fits.
const (
	MobileDecodedBudget  int64 = 24 * 1024 * 1024 // PLATE_DECODED_BUDGET_MOBILE
	DesktopDecodedBudget int64 = 96 * 1024 * 1024 // PLATE_DECODED_BUDGET_DESKTOP
)

// smallViewportThreshold: at or below this CSS px width, take the mobile budget
// regardless of anything else. A phone viewport ALONE is sufficient (spec §4.2).
const smallViewportThreshold = 768

// ClientHints are the inputs the client actually has when choosing a device
// class — the same inputs `deviceBudgetBytes()` reads in the browser (spec
// §4.2). deviceMemory is Chromium-only and ABSENT on Safari, the browser that
// actually dies, so the resolver must never depend on it being present.
type ClientHints struct {
	// DeviceParam is the explicit `device` query value, if the caller sent one.
	// Empty means unspecified.
	DeviceParam string
	// DeviceMemoryPresent is false on Safari (navigator.deviceMemory is
	// undefined there). It must NOT be a precondition for the mobile budget.
	DeviceMemoryPresent bool
	// DeviceMemoryGiB is navigator.deviceMemory when present (e.g. 8). Ignored
	// when DeviceMemoryPresent is false.
	DeviceMemoryGiB float64
	// ViewportWidth is window.innerWidth in CSS px, 0 if unknown.
	ViewportWidth int
}

// ResolveDeviceClass picks the device class from client hints, failing toward
// the SAFE (mobile) budget. The rules, in order (spec §4.2):
//
//  1. An explicit, valid `device` param wins.
//  2. A small viewport ALONE takes mobile — never gated on deviceMemory, which
//     is absent on Safari.
//  3. Low reported deviceMemory (when present) takes mobile.
//  4. Default is mobile when nothing indicates a roomy desktop.
//
// Desktop is only chosen on positive evidence of a roomy client (a wide viewport
// and, if deviceMemory is known, enough of it). Absence of information → mobile.
func ResolveDeviceClass(h ClientHints) plate.DeviceClass {
	// 1. Explicit param wins, if valid.
	switch plate.DeviceClass(h.DeviceParam) {
	case plate.Mobile:
		return plate.Mobile
	case plate.Desktop:
		return plate.Desktop
	}

	// 2. Small viewport alone → mobile. This is the Safari path: deviceMemory is
	//    absent, but a narrow viewport is enough on its own.
	if h.ViewportWidth > 0 && h.ViewportWidth <= smallViewportThreshold {
		return plate.Mobile
	}

	// 3. Known-low memory → mobile.
	if h.DeviceMemoryPresent && h.DeviceMemoryGiB > 0 && h.DeviceMemoryGiB < 4 {
		return plate.Mobile
	}

	// 4. Desktop only on positive evidence of a roomy client: a wide viewport.
	//    With no viewport information at all, fail safe to mobile.
	if h.ViewportWidth > smallViewportThreshold {
		return plate.Desktop
	}
	return plate.Mobile
}

// DecodedBudgetFor returns the decoded-RGBA byte budget for a device class.
func DecodedBudgetFor(class plate.DeviceClass) int64 {
	if class == plate.Desktop {
		return DesktopDecodedBudget
	}
	return MobileDecodedBudget
}

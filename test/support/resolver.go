// Package support holds the thin service SEAMS the test suite drives, plus
// reference stubs standing in for the not-yet-written service.
//
// Why this exists: the tests are the deliverable this round; the service is not
// written yet (spec §7 — tests come first). Where a test needs "the service" to
// run against, it drives a small interface declared here and a minimal reference
// stub. When the real service lands, it implements these interfaces and the
// stubs are deleted — the ASSERTIONS in the tests do not change, because they
// check the real artifact (the probed duration, the decoded pixels, the box
// order), never a recorded mock call.
//
// Each stub encodes ONLY the decision under test, fed by an artifact-derived
// input it does not get to fabricate. The ceiling resolver's sole input is the
// ffprobe-measured duration; it cannot invent a duration to make itself pass.
package support

import (
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// DetailResolver decides whether a `detail`-intent delivery can exist for a
// source of a given (measured) duration, or must be refused. The service will
// implement this over its real asset/rendition state; the test drives it with a
// duration ffprobe measured off a real file.
type DetailResolver interface {
	ResolveDetail(measuredDurationS float64) plate.DeliveryResolution
}

// ceilingResolver is the reference stub: refuse when the measured duration
// exceeds the configured ceiling, carrying the closed-enum reason and the
// machine-readable detail Files needs (spec §4.3).
type ceilingResolver struct {
	ceilingS float64
}

// NewCeilingResolver returns a DetailResolver enforcing a duration ceiling in
// seconds (spec §5.4: PLATE_DETAIL_MAX_DURATION, default 720s).
func NewCeilingResolver(ceilingS float64) DetailResolver {
	return ceilingResolver{ceilingS: ceilingS}
}

func (r ceilingResolver) ResolveDetail(measuredDurationS float64) plate.DeliveryResolution {
	if measuredDurationS > r.ceilingS {
		reason := plate.ReasonCodeExceededDurationCeiling
		d := measuredDurationS
		c := r.ceilingS
		return plate.DeliveryResolution{
			Intent:   plate.Detail,
			Delivery: nil,
			Reason:   &reason,
			Detail: &plate.RefusalDetail{
				DurationS: &d,
				CeilingS:  &c,
			},
		}
	}
	// Under the ceiling: a delivery is possible. The stub does not build a real
	// URL (that is worker/imgproxy work, exercised elsewhere); it returns a
	// non-nil delivery to signal "not refused for duration".
	return plate.DeliveryResolution{
		Intent: plate.Detail,
		Delivery: &plate.Delivery{
			Url:  "stub://detail", // placeholder; real URL is the worker's job
			Mode: plate.Signed,
		},
	}
}

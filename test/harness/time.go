package harness

import "time"

// Seconds is a tiny convenience so test files can express fixture durations
// without each importing time. Seconds(90) == 90s; Seconds(13*60) == 13 minutes.
func Seconds(n float64) time.Duration {
	return time.Duration(n * float64(time.Second))
}

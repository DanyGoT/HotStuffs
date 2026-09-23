package hotstuff

import "time"

// Duration is the view timer's backoff policy: it grows the view timeout by a
// factor on every consecutive timeout, capped at max, and resets it when a
// view succeeds.
type Duration struct {
	base, max time.Duration
	factor    float64
	current   time.Duration
}

// NewDuration returns a view timer policy starting at base.
func NewDuration(base, max time.Duration, factor float64) *Duration {
	return &Duration{base: base, max: max, factor: factor, current: base}
}

func (d *Duration) Duration() time.Duration { return d.current }

// ViewStarted is a no-op: exponential backoff needs no view latency. A
// measurement-based policy would use it.
func (d *Duration) ViewStarted() {}

func (d *Duration) ViewSucceeded() { d.current = d.base }

func (d *Duration) ViewTimedOut() {
	d.current = min(time.Duration(float64(d.current)*d.factor), d.max)
}

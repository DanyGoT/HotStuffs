package consensus

import (
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// ExponentialDuration grows the view timeout by a factor on every consecutive
// timeout, capped at max, and resets it when a view succeeds.
type ExponentialDuration struct {
	base, max time.Duration
	factor    float64
	current   time.Duration
}

// NewViewDuration returns a view timer policy starting at base.
func NewViewDuration(base, max time.Duration, factor float64) *ExponentialDuration {
	return &ExponentialDuration{base: base, max: max, factor: factor, current: base}
}

func (d *ExponentialDuration) Duration() time.Duration { return d.current }

// ViewStarted is a no-op: exponential backoff needs no view latency. A
// measurement-based policy would use it.
func (d *ExponentialDuration) ViewStarted() {}

func (d *ExponentialDuration) ViewSucceeded() { d.current = d.base }

func (d *ExponentialDuration) ViewTimedOut() {
	d.current = min(time.Duration(float64(d.current)*d.factor), d.max)
}

var _ hotstuff.ViewDuration = (*ExponentialDuration)(nil)

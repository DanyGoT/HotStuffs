package fake

import (
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Clock is a clock driven by hand: timers fire only from Advance, in deadline
// order with insertion order breaking ties. Sharing one across replicas is what
// makes a multi-replica simulation reproducible.
type Clock struct {
	now     time.Time
	pending []*timer
	seq     uint64
}

type timer struct {
	deadline time.Time
	seq      uint64
	fn       func()
	clock    *Clock
}

// NewClock returns a clock reading start.
func NewClock(start time.Time) *Clock { return &Clock{now: start} }

func (c *Clock) Now() time.Time { return c.now }

func (c *Clock) AfterFunc(d time.Duration, fn func()) hotstuff.Timer {
	c.seq++
	t := &timer{deadline: c.now.Add(d), seq: c.seq, fn: fn, clock: c}
	c.pending = append(c.pending, t)
	return t
}

// Stop cancels the timer, reporting whether it had not already fired.
func (t *timer) Stop() bool {
	for i, p := range t.clock.pending {
		if p == t {
			t.clock.pending = append(t.clock.pending[:i], t.clock.pending[i+1:]...)
			return true
		}
	}
	return false
}

// Advance moves time forward by d, firing every timer whose deadline it passes.
// A callback may schedule new timers; they fire in this call only if their
// deadline also falls within d.
func (c *Clock) Advance(d time.Duration) {
	target := c.now.Add(d)
	for {
		next := c.earliest(target)
		if next == nil {
			c.now = target
			return
		}
		c.now = next.deadline
		next.Stop()
		next.fn()
	}
}

// Pending is the number of armed timers.
func (c *Clock) Pending() int { return len(c.pending) }

func (c *Clock) earliest(by time.Time) *timer {
	var best *timer
	for _, t := range c.pending {
		if t.deadline.After(by) {
			continue
		}
		if best == nil || t.deadline.Before(best.deadline) || (t.deadline.Equal(best.deadline) && t.seq < best.seq) {
			best = t
		}
	}
	return best
}

var _ hotstuff.Clock = (*Clock)(nil)

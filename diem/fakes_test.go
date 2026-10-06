package diem

import (
	"bytes"
	"time"
)

// testSigner is a stand-in for real crypto: a signature is the signed digest
// itself, so a wrong-digest bug still fails, but there is no key material and
// no randomness.
type testSigner struct{ n int }

func newTestSigner(n int) *testSigner { return &testSigner{n: n} }

func (s *testSigner) Sign(digest []byte) ([]byte, error) { return bytes.Clone(digest), nil }

// Verify checks that signer is a replica in 1..n and sig carries digest itself.
func (s *testSigner) Verify(signer uint32, digest, sig []byte) bool {
	if signer < 1 || uint64(signer) > uint64(s.n) {
		return false
	}
	return bytes.Equal(sig, digest)
}

// fakeClock is a clock driven by hand: timers fire only from Advance, in
// deadline order with insertion order breaking ties. Sharing one across
// replicas is what makes a multi-replica simulation reproducible.
type fakeClock struct {
	now     time.Time
	pending []*fakeTimer
	seq     uint64
}

type fakeTimer struct {
	deadline time.Time
	seq      uint64
	fn       func()
	clock    *fakeClock
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(0, 0)} }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) AfterFunc(d time.Duration, fn func()) Timer {
	c.seq++
	t := &fakeTimer{deadline: c.now.Add(d), seq: c.seq, fn: fn, clock: c}
	c.pending = append(c.pending, t)
	return t
}

// Stop cancels the timer, reporting whether it had not already fired.
func (t *fakeTimer) Stop() bool {
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
func (c *fakeClock) Advance(d time.Duration) {
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

func (c *fakeClock) earliest(by time.Time) *fakeTimer {
	var best *fakeTimer
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

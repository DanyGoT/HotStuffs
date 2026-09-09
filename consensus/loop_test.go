package consensus

import (
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

func TestTickProcessesExactlyOneEvent(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var bh hotstuff.Hash
	bh[0] = 0x10
	h.loop.Push(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 1, 1, bh)})
	h.loop.Push(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, bh)})
	h.loop.Push(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, 1, bh)})

	if !h.loop.Tick() || h.core.State().View != 1 {
		t.Fatalf("after tick 1: View = %d, want 1 (only one vote processed)", h.core.State().View)
	}
	if !h.loop.Tick() || h.core.State().View != 1 {
		t.Fatalf("after tick 2: View = %d, want still 1", h.core.State().View)
	}
	if !h.loop.Tick() || h.core.State().View != 2 {
		t.Fatalf("after tick 3: View = %d, want 2 (quorum reached)", h.core.State().View)
	}
	if h.loop.Tick() {
		t.Errorf("a fourth Tick() returned true on an empty queue")
	}
}

func TestLoopReceivesTimerEvents(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	if got := h.clk.Pending(); got != 1 {
		t.Fatalf("clk.Pending() = %d, want 1 after Start()", got)
	}

	h.clk.Advance(baseDuration)
	if !h.loop.Tick() {
		t.Fatalf("Tick() = false, want true: the fired timer should have queued a ViewTimeoutEvent")
	}
	if len(h.tr.Timeouts) != 1 {
		t.Errorf("Timeouts = %d entries, want 1", len(h.tr.Timeouts))
	}
}

func TestStopDisarmsTimer(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	h.core.Stop()
	if got := h.clk.Pending(); got != 0 {
		t.Fatalf("clk.Pending() = %d, want 0 after Stop()", got)
	}

	h.clk.Advance(baseDuration)
	if len(h.tr.Timeouts) != 0 {
		t.Errorf("Timeouts = %d entries, want 0: a stopped timer must not fire", len(h.tr.Timeouts))
	}
	if h.loop.Tick() {
		t.Errorf("Tick() = true, want false: no event should have been queued")
	}
}

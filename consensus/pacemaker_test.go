package consensus

import (
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

func TestViewTimeoutBroadcastsOnce(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start() // arms the view-1 timer at the base duration

	h.clk.Advance(baseDuration)
	for h.loop.Tick() {
	}
	if len(h.tr.Timeouts) != 1 {
		t.Fatalf("Timeouts = %d entries, want 1", len(h.tr.Timeouts))
	}
	msg := h.tr.Timeouts[0]
	if got := h.core.State().View; msg.View != got {
		t.Errorf("Timeout.View = %d, want current view %d", msg.View, got)
	}
	if msg.HighQC.View != h.core.State().HighQC.View || msg.HighQC.BlockHash != h.core.State().HighQC.BlockHash {
		t.Errorf("Timeout.HighQC = %+v, want %+v", msg.HighQC, h.core.State().HighQC)
	}

	// the duration has grown; advancing by it fires exactly one more timeout.
	h.clk.Advance(h.dur.Duration())
	for h.loop.Tick() {
	}
	if len(h.tr.Timeouts) != 2 {
		t.Errorf("Timeouts = %d entries, want 2", len(h.tr.Timeouts))
	}
}

func TestTimeoutQuorumFormsTCAndAdvances(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start() // view 1
	qc := h.core.State().HighQC

	h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 2, 1, qc)})
	h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 2, 1, qc)}) // duplicate signer
	if got := h.core.State().View; got != 1 {
		t.Fatalf("View = %d, want still 1 after one distinct signer plus a repeat", got)
	}

	h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 3, 1, qc)})
	if got := h.core.State().View; got != 1 {
		t.Fatalf("View = %d, want still 1: sub-quorum", got)
	}

	h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 4, 1, qc)})
	if got := h.core.State().View; got != 2 {
		t.Errorf("View = %d, want 2 once a quorum of distinct timeouts arrives", got)
	}
}

func TestTimeoutCarriesHighQCForward(t *testing.T) {
	t.Run("future view raises highQC despite no quorum yet", func(t *testing.T) {
		h := newHarness(t, 1, 4)
		h.core.Start() // view 1, highQC view 0

		future := hotstuff.QuorumCert{View: 5, BlockHash: hotstuff.Hash{0x55}}
		h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 2, 9, future)})

		if got := h.core.State().HighQC.View; got != 5 {
			t.Errorf("HighQC.View = %d, want 5", got)
		}
	})

	t.Run("a stale view's timeout is not counted but its QC is taken", func(t *testing.T) {
		h := newHarness(t, 1, 4)
		h.core.Start()
		h.core.view = 10 // simulate having moved well past view 1

		older := hotstuff.QuorumCert{View: 3, BlockHash: hotstuff.Hash{0x33}}
		h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 2, 1, older)})

		if got := h.core.State().HighQC.View; got != 3 {
			t.Errorf("HighQC.View = %d, want 3 even though the timeout's view is stale", got)
		}
		if n := len(h.core.timeouts); n != 0 {
			t.Errorf("timeouts has %d entries, want 0: view 1 is stale against view 10", n)
		}
	})
}

func TestStaleViewTimeoutEventIgnored(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start() // view 1

	h.core.Step(hotstuff.ViewTimeoutEvent{View: 0})
	h.core.Step(hotstuff.ViewTimeoutEvent{View: 2})

	if len(h.tr.Timeouts) != 0 {
		t.Errorf("Timeouts = %d entries, want 0 for a stale/future ViewTimeoutEvent", len(h.tr.Timeouts))
	}
}

func TestTimeoutCertJustifiesProposal(t *testing.T) {
	h := newHarness(t, 1, 4) // replica 1 leads view 4
	h.core.Start()

	// Reach view 3 purely through vote-formed QCs (signers 2,3,4 - a quorum on
	// their own), since replica 1 does not lead views 1-3.
	for _, v := range []hotstuff.View{1, 2} {
		var bh hotstuff.Hash
		bh[0] = byte(v)
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, v, bh)})
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, v, bh)})
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 4, v, bh)})
	}
	if got := h.core.State().View; got != 3 {
		t.Fatalf("View = %d, want 3 before the timeout round", got)
	}

	for _, signer := range []hotstuff.ID{2, 3, 4} {
		h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, signer, 3, h.core.State().HighQC)})
	}
	if got := h.core.State().View; got != 4 {
		t.Fatalf("View = %d, want 4 after the view-3 TC forms", got)
	}

	if len(h.tr.Proposals) != 1 {
		t.Fatalf("Proposals = %d entries, want 1", len(h.tr.Proposals))
	}
	p := h.tr.Proposals[0]
	if p.TC == nil || p.TC.View != 3 {
		t.Errorf("Proposal.TC = %v, want a TC for view 3", p.TC)
	}
}

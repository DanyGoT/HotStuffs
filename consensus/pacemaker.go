package consensus

import "github.com/DanyGoT/HotStuffs/hotstuff"

// Algorithm 5, in the same struct as Algorithm 4: updateHighQC writes state
// that propose reads and the commit path calls it, so splitting them would be a
// false seam that an event loop then has to reconnect.

// advanceView is the one entry point for entering a new view, called from
// exactly three places: a QC formed locally, a QC seen in a proposal, and a TC
// formed.
func (c *Core) advanceView(si hotstuff.SyncInfo) {
	c.updateHighQC(si.QC)
	c.prune()
	next := si.View()
	if next <= c.view {
		return
	}
	if si.TC == nil {
		c.dur.ViewSucceeded()
	}
	c.view = next
	c.dur.ViewStarted()
	c.resetTimer()
	if c.leader(next) == c.id {
		c.propose(justifyingTC(si, next))
	}
}

// justifyingTC is the TimeoutCert a proposal for v must carry, or nil when v's
// entry is already justified by the QC alone.
func justifyingTC(si hotstuff.SyncInfo, v hotstuff.View) *hotstuff.TimeoutCert {
	if si.QC.View+1 == v {
		return nil
	}
	return si.TC
}

// updateHighQC never dereferences a block. A QuorumCert carries its own view,
// so a QC for a block that was never seen is still usable, which is what
// removes any need for vote continuations.
func (c *Core) updateHighQC(qc hotstuff.QuorumCert) {
	if qc.View > c.highQC.View {
		c.highQC = qc
	}
}

// updateLock raises the lock to the view two certificates back — the paper's
// b_lock ← b'. When the certified block is absent this replica is behind, and
// leaving the lock stale is safe: its own vote cannot form a quorum, and every
// replica that voted in a committed chain did hold the blocks.
func (c *Core) updateLock(qc hotstuff.QuorumCert) {
	b, ok := c.store.Get(qc.BlockHash)
	if !ok {
		return
	}
	if v := b.QC().View; v > c.lockedView {
		c.lockedView = v
	}
}

// prune drops accumulator entries that can no longer matter, so none of them
// grows without bound.
func (c *Core) prune() {
	for h, vs := range c.votes {
		if vs.view <= c.highQC.View {
			delete(c.votes, h)
		}
	}
	for v := range c.timeouts {
		if v < c.view {
			delete(c.timeouts, v)
		}
	}
	for h := range c.fetching {
		if _, ok := c.store.Get(h); ok {
			delete(c.fetching, h)
		}
	}
}

func (c *Core) resetTimer() {
	if c.timer != nil {
		c.timer.Stop()
	}
	v := c.view
	// GORUMS: Gorums ships no timer or scheduler, so the protocol owns its
	// clock. The callback runs off the consensus goroutine and may therefore
	// only enqueue.
	c.timer = c.clock.AfterFunc(c.dur.Duration(), func() {
		c.sink.Push(hotstuff.ViewTimeoutEvent{View: v})
	})
}

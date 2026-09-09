// Package consensus is the protocol core: the event-driven state machine, the
// pacemaker, and the chained HotStuff rules. It knows nothing about protobuf or
// Gorums, and it runs on a single goroutine, so it holds no locks.
package consensus

import "github.com/DanyGoT/HotStuffs/hotstuff"

// chainLength is how many consecutive certified views a commit needs.
const chainLength = 3

// chained implements the three decisions that define Chained HotStuff.
type chained struct {
	id    hotstuff.ID
	store hotstuff.BlockStore
}

// NewRules returns the Chained HotStuff ruleset for replica id.
func NewRules(id hotstuff.ID, store hotstuff.BlockStore) hotstuff.Rules {
	return chained{id: id, store: store}
}

func (chained) ChainLength() int { return chainLength }

// VoteRule is the DiemBFT formulation, a deliberate deviation from Algorithm 4.
// The paper's "bNew extends bLock ∨ qc.height > bLock.height" disjunction
// collapses to qc.View >= LockedView: voting at most once per view means at most
// one block per view can obtain a QC, so a QC at exactly LockedView certifies
// exactly the locked block. The payoff is that voting never walks the chain, so
// a replica that missed blocks stays live and backfills lazily.
func (chained) VoteRule(s hotstuff.State, p hotstuff.Proposal) bool {
	return p.Block.View() > s.LastVotedView && p.Block.QC().View >= s.LockedView
}

// ProposeRule extends the highest QC in the current view. The Proposal comes
// back unsigned; signing is the caller's job.
func (r chained) ProposeRule(s hotstuff.State, cmds [][]byte, tc *hotstuff.TimeoutCert) (hotstuff.Proposal, bool) {
	if s.HighQC.View >= s.View {
		return hotstuff.Proposal{}, false
	}
	b := hotstuff.NewBlock(s.HighQC.BlockHash, s.View, r.id, s.HighQC, cmds)
	return hotstuff.Proposal{Block: b, TC: tc}, true
}

// CommitRule is the 3-chain rule. Walking back one certificate at a time from b
// gives chainLength blocks; the last commits when they are parent-linked and
// their views are consecutive. Requiring consecutive views is what the paper's
// dummy blocks would otherwise have guaranteed.
//
// b's own view plays no part: b carries no certificate for itself, only the
// third one for the chain below it. So a block proposed across a view-change gap
// still commits the consecutive history beneath it.
func (r chained) CommitRule(_ hotstuff.State, b *hotstuff.Block) (*hotstuff.Block, hotstuff.Hash) {
	var c [chainLength]*hotstuff.Block
	cur := b
	for i := range c {
		if cur.View() == 0 { // genesis certifies nothing
			return nil, hotstuff.Hash{}
		}
		next, ok := r.store.Get(cur.QC().BlockHash)
		if !ok {
			return nil, cur.QC().BlockHash
		}
		c[i], cur = next, next
	}
	for i := 1; i < len(c); i++ {
		if c[i-1].Parent() != c[i].Hash() || c[i].View()+1 != c[i-1].View() {
			return nil, hotstuff.Hash{}
		}
	}
	return c[len(c)-1], hotstuff.Hash{}
}

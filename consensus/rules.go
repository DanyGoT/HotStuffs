// Package consensus is the protocol core: the event-driven state machine, the
// pacemaker, and the chained HotStuff rules. It knows nothing about protobuf or
// Gorums, and it runs on a single goroutine, so it holds no locks.
package consensus

import (
	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// chainLength is how many consecutive certified views a commit needs.
const chainLength = 3

// Chained is the protocol variant: the three decisions that differ between
// HotStuff flavours, in the form that defines Chained HotStuff. Every method
// is a pure function of the snapshot it is given plus the block store, which
// is what makes it table-testable.
type Chained struct {
	id    hotstuff.ID
	store *blockchain.Store
}

// NewRules returns the Chained HotStuff ruleset for replica id.
func NewRules(id hotstuff.ID, store *blockchain.Store) *Chained {
	return &Chained{id: id, store: store}
}

// VoteRule is Algorithm 3's safeNode in the form the one-block-per-view lemma
// permits. safeNode is "bNew extends bLock ∨ bNew.justify.height >
// bLock.height"; an honest replica votes at most once per view, so at most one
// block per view can obtain a QC, so a QC at exactly LockedView certifies
// exactly the locked block and the extends branch collapses into
// qc.View >= LockedView.
//
// The store lookup is what keeps the lock resolvable. Algorithm 5 sets
// bLock ← b', the block this proposal's QC certifies, and a replica that does
// not hold b' cannot take that lock: it would join the quorum certifying the
// 3-chain while its own lock stayed behind, which is the one case the chain's
// safety argument assumes away. It is one O(1) lookup, one level deep, so
// voting still never walks the chain. Carrying the parent's view inside the
// QuorumCert would resolve the lock too, but that is DiemBFT's design and it
// changes both the wire format and the vote digest, for nothing this does not
// already give.
func (r *Chained) VoteRule(s hotstuff.State, p hotstuff.Proposal) bool {
	if p.Block.View() <= s.LastVotedView || p.Block.QC().View < s.LockedView {
		return false
	}
	_, held := r.store.Get(p.Block.QC().BlockHash)
	return held
}

// ProposeRule extends the highest QC in the current view. The Proposal comes
// back unsigned; signing is the caller's job, so the rules stay crypto-free.
func (r *Chained) ProposeRule(s hotstuff.State, cmds [][]byte, tc *hotstuff.TimeoutCert) (hotstuff.Proposal, bool) {
	if s.HighQC.View >= s.View {
		return hotstuff.Proposal{}, false
	}
	b := hotstuff.NewBlock(s.HighQC.BlockHash, s.View, r.id, s.HighQC, cmds)
	return hotstuff.Proposal{Block: b, TC: tc}, true
}

// CommitRule returns the highest block committed as a consequence of b being
// stored, or nil; if the decision needs an absent ancestor it returns (nil,
// thatHash), and otherwise missing is the zero Hash.
//
// It is the 3-chain rule. Walking back one certificate at a time from b gives
// chainLength blocks; the last commits when they are parent-linked and their
// views are consecutive. Requiring consecutive views is what the paper's
// dummy blocks would otherwise have guaranteed.
//
// b's own view plays no part: b carries no certificate for itself, only the
// third one for the chain below it. So a block proposed across a view-change gap
// still commits the consecutive history beneath it.
func (r *Chained) CommitRule(_ hotstuff.State, b *hotstuff.Block) (*hotstuff.Block, hotstuff.Hash) {
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

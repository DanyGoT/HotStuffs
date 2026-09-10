package consensus_test

import (
	"bytes"
	"testing"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/consensus"
	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// chain returns blocks for the given views, each extending the previous and
// carrying a QC for it, rooted at genesis. Views need not be consecutive: that
// is exactly what the commit rule cares about.
func chain(views ...hotstuff.View) []*hotstuff.Block {
	blocks := make([]*hotstuff.Block, len(views))
	parent := hotstuff.Genesis()
	for i, v := range views {
		qc := hotstuff.QuorumCert{View: parent.View(), BlockHash: parent.Hash()}
		blocks[i] = hotstuff.NewBlock(parent.Hash(), v, 1, qc, nil)
		parent = blocks[i]
	}
	return blocks
}

func TestVoteRule(t *testing.T) {
	// Every case below certifies genesis, which the store always holds, so
	// the table isolates the view arithmetic; the absent-parent branch is
	// checked on its own afterwards.
	tests := []struct {
		name          string
		lastVotedView hotstuff.View
		lockedView    hotstuff.View
		blockView     hotstuff.View
		qcView        hotstuff.View
		want          bool
	}{
		{"new view, qc above lock", 4, 2, 5, 3, true},
		// At most one block per view can obtain a QC, so a QC at exactly
		// LockedView certifies exactly the locked block.
		{"new view, qc equal to lock", 4, 3, 5, 3, true},
		{"new view, qc one below lock", 4, 3, 5, 2, false},
		{"repeat view, fresh qc", 5, 2, 5, 4, false},
		{"repeat view, stale qc", 5, 5, 5, 1, false},
		{"stale view", 5, 2, 4, 3, false},
		{"first block", 0, 0, 1, 0, true},
		{"large gap, fresh qc", 1, 50, 1000, 60, true},
		{"large gap, qc below lock", 1, 50, 1000, 10, false},
	}
	r := consensus.NewRules(1, blockchain.New())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := hotstuff.State{LastVotedView: tt.lastVotedView, LockedView: tt.lockedView}
			qc := hotstuff.QuorumCert{View: tt.qcView, BlockHash: hotstuff.GenesisHash()}
			b := hotstuff.NewBlock(hotstuff.GenesisHash(), tt.blockView, 1, qc, nil)
			if got := r.VoteRule(s, hotstuff.Proposal{Block: b}); got != tt.want {
				t.Errorf("VoteRule() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("certified block absent", func(t *testing.T) {
		var missing hotstuff.Hash
		missing[0] = 0x42
		qc := hotstuff.QuorumCert{View: 3, BlockHash: missing}
		b := hotstuff.NewBlock(missing, 5, 1, qc, nil)
		s := hotstuff.State{LastVotedView: 4, LockedView: 2}
		if r.VoteRule(s, hotstuff.Proposal{Block: b}) {
			t.Error("VoteRule() = true, want false: a lock cannot be raised to a block the store lacks")
		}
	})
}

func TestCommitRule(t *testing.T) {
	t.Run("three consecutive views commit", func(t *testing.T) {
		store := blockchain.New()
		blocks := chain(1, 2, 3, 4)
		for _, b := range blocks {
			store.Put(b)
		}
		b1, b3, b4 := blocks[0], blocks[2], blocks[3]
		r := consensus.NewRules(1, store)

		if commit, missing := r.CommitRule(hotstuff.State{}, b4); commit != b1 || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b4) = (%v, %x), want (b1, zero)", commit, missing)
		}

		// The walk from b3 reaches genesis, whose views 0,1,2 are consecutive
		// and parent-linked, so genesis is what the rule names here. The core
		// filters it out separately, since genesis's view is not above the
		// committed view; this only pins what the rule itself returns.
		if commit, missing := r.CommitRule(hotstuff.State{}, b3); commit != hotstuff.Genesis() || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b3) = (%v, %x), want (Genesis, zero)", commit, missing)
		}
	})

	t.Run("longer chain", func(t *testing.T) {
		store := blockchain.New()
		blocks := chain(1, 2, 3, 4, 5, 6)
		for _, b := range blocks {
			store.Put(b)
		}
		b2, b3, b5, b6 := blocks[1], blocks[2], blocks[4], blocks[5]
		r := consensus.NewRules(1, store)

		if commit, missing := r.CommitRule(hotstuff.State{}, b6); commit != b3 || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b6) = (%v, %x), want (b3, zero)", commit, missing)
		}
		if commit, missing := r.CommitRule(hotstuff.State{}, b5); commit != b2 || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b5) = (%v, %x), want (b2, zero)", commit, missing)
		}
	})

	t.Run("non-consecutive views commit nothing", func(t *testing.T) {
		store := blockchain.New()
		blocks := chain(1, 3, 4, 5)
		for _, b := range blocks {
			store.Put(b)
		}
		r := consensus.NewRules(1, store)
		// Covers a gap at each of the two positions the walk checks: 4-3-1
		// (queried at view 4) fails on the newer pair, 5-4-3-1 (queried at the
		// tip) fails on the older pair.
		for _, b := range blocks {
			if commit, missing := r.CommitRule(hotstuff.State{}, b); commit != nil || missing != (hotstuff.Hash{}) {
				t.Errorf("CommitRule(view %d) = (%v, %x), want (nil, zero)", b.View(), commit, missing)
			}
		}
	})

	t.Run("a gap right below the queried block is invisible to the rule", func(t *testing.T) {
		// CommitRule never compares b's own view against the chain it walks
		// back to: b has no QC of its own yet, so only the three ancestors it
		// names (c[0..2]) must be mutually consecutive. Querying the chain's
		// tip (b5) hits the gap normally, but querying the block that sits
		// right above the gap (b4, view 4, QC'ing view 2) does not: b4's QC
		// still opens onto a fully consecutive, parent-linked 2-1-0, so the
		// rule commits genesis exactly as it would from a genuinely
		// consecutive b3.
		store := blockchain.New()
		blocks := chain(1, 2, 4, 5)
		b1, b2, b4, b5 := blocks[0], blocks[1], blocks[2], blocks[3]
		for _, b := range blocks {
			store.Put(b)
		}
		r := consensus.NewRules(1, store)

		if commit, missing := r.CommitRule(hotstuff.State{}, b5); commit != nil || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b5) = (%v, %x), want (nil, zero)", commit, missing)
		}
		if commit, missing := r.CommitRule(hotstuff.State{}, b4); commit != hotstuff.Genesis() || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b4) = (%v, %x), want (Genesis, zero)", commit, missing)
		}
		if commit, missing := r.CommitRule(hotstuff.State{}, b1); commit != nil || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b1) = (%v, %x), want (nil, zero)", commit, missing)
		}
		if commit, missing := r.CommitRule(hotstuff.State{}, b2); commit != nil || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b2) = (%v, %x), want (nil, zero)", commit, missing)
		}
	})

	t.Run("broken parent link commits nothing", func(t *testing.T) {
		store := blockchain.New()
		base := chain(1, 2)
		b1, b2 := base[0], base[1]
		store.Put(b1)
		store.Put(b2)
		// b3's QC still certifies b2, but its parent points at genesis instead:
		// a broken link the walk must catch even though every ancestor it
		// fetches is present.
		b3 := hotstuff.NewBlock(hotstuff.GenesisHash(), 3, 1, hotstuff.QuorumCert{View: b2.View(), BlockHash: b2.Hash()}, nil)
		b4 := hotstuff.NewBlock(b3.Hash(), 4, 1, hotstuff.QuorumCert{View: b3.View(), BlockHash: b3.Hash()}, nil)
		store.Put(b3)
		store.Put(b4)
		r := consensus.NewRules(1, store)

		if commit, missing := r.CommitRule(hotstuff.State{}, b4); commit != nil || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b4) = (%v, %x), want (nil, zero)", commit, missing)
		}
	})

	t.Run("missing ancestor returns that hash", func(t *testing.T) {
		blocks := chain(1, 2, 3, 4)
		b1, b2, b3, b4 := blocks[0], blocks[1], blocks[2], blocks[3]

		store := blockchain.New()
		store.Put(b2)
		store.Put(b3)
		store.Put(b4)
		r := consensus.NewRules(1, store)
		if commit, missing := r.CommitRule(hotstuff.State{}, b4); commit != nil || missing != b1.Hash() {
			t.Errorf("CommitRule(b4) with b1 missing = (%v, %x), want (nil, %x)", commit, missing, b1.Hash())
		}

		// Omitting b2 as well: the walk now hits that gap first.
		store2 := blockchain.New()
		store2.Put(b3)
		store2.Put(b4)
		r2 := consensus.NewRules(1, store2)
		if commit, missing := r2.CommitRule(hotstuff.State{}, b4); commit != nil || missing != b2.Hash() {
			t.Errorf("CommitRule(b4) with b1,b2 missing = (%v, %x), want (nil, %x)", commit, missing, b2.Hash())
		}
	})

	t.Run("genesis stops the walk", func(t *testing.T) {
		store := blockchain.New()
		b1 := chain(1)[0]
		store.Put(b1)
		r := consensus.NewRules(1, store)

		if commit, missing := r.CommitRule(hotstuff.State{}, b1); commit != nil || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(b1) = (%v, %x), want (nil, zero)", commit, missing)
		}
		if commit, missing := r.CommitRule(hotstuff.State{}, hotstuff.Genesis()); commit != nil || missing != (hotstuff.Hash{}) {
			t.Errorf("CommitRule(Genesis) = (%v, %x), want (nil, zero)", commit, missing)
		}
	})

	t.Run("state argument is ignored", func(t *testing.T) {
		store := blockchain.New()
		blocks := chain(1, 2, 3, 4)
		for _, b := range blocks {
			store.Put(b)
		}
		r := consensus.NewRules(1, store)

		c1, m1 := r.CommitRule(hotstuff.State{}, blocks[3])
		wild := hotstuff.State{View: 99, LastVotedView: 50, LockedView: 30, CommittedView: 10, HighQC: hotstuff.QuorumCert{View: 77}}
		c2, m2 := r.CommitRule(wild, blocks[3])
		if c1 != c2 || m1 != m2 {
			t.Errorf("CommitRule results differ across State values: (%v, %x) vs (%v, %x)", c1, m1, c2, m2)
		}
	})
}

func TestProposeRule(t *testing.T) {
	id := hotstuff.ID(7)
	r := consensus.NewRules(id, blockchain.New())

	t.Run("normal proposal", func(t *testing.T) {
		hq := hotstuff.QuorumCert{View: 4, BlockHash: hotstuff.Hash{0x11}}
		s := hotstuff.State{View: 5, HighQC: hq}
		cmds := [][]byte{[]byte("a"), []byte("b")}

		p, ok := r.ProposeRule(s, cmds, nil)
		if !ok {
			t.Fatal("ProposeRule() ok = false, want true")
		}
		if p.Block.View() != 5 {
			t.Errorf("Block.View() = %d, want 5", p.Block.View())
		}
		if p.Block.Proposer() != id {
			t.Errorf("Block.Proposer() = %d, want %d", p.Block.Proposer(), id)
		}
		if p.Block.Parent() != hq.BlockHash {
			t.Errorf("Block.Parent() = %x, want %x", p.Block.Parent(), hq.BlockHash)
		}
		if got := p.Block.QC(); got.View != hq.View || got.BlockHash != hq.BlockHash {
			t.Errorf("Block.QC() = %+v, want %+v", got, hq)
		}
		gotCmds := p.Block.Cmds()
		if len(gotCmds) != len(cmds) {
			t.Fatalf("Cmds() has %d entries, want %d", len(gotCmds), len(cmds))
		}
		for i := range cmds {
			if !bytes.Equal(gotCmds[i], cmds[i]) {
				t.Errorf("Cmds()[%d] = %q, want %q", i, gotCmds[i], cmds[i])
			}
		}
		if p.TC != nil {
			t.Errorf("TC = %v, want nil", p.TC)
		}
		// Signing is the caller's job: the rule must return the Proposal unsigned.
		if p.Sig.Signer != 0 || len(p.Sig.Data) != 0 {
			t.Errorf("Sig = %+v, want zero value", p.Sig)
		}
	})

	t.Run("TC carried through unchanged", func(t *testing.T) {
		s := hotstuff.State{View: 5, HighQC: hotstuff.QuorumCert{View: 4}}
		tc := &hotstuff.TimeoutCert{View: 4, Sigs: []hotstuff.Signature{{Signer: 2}}}

		p, ok := r.ProposeRule(s, nil, tc)
		if !ok {
			t.Fatal("ProposeRule() ok = false, want true")
		}
		if p.TC != tc {
			t.Errorf("TC = %p, want the same pointer %p", p.TC, tc)
		}
	})

	t.Run("refused when HighQC view equals State view", func(t *testing.T) {
		s := hotstuff.State{View: 4, HighQC: hotstuff.QuorumCert{View: 4}}
		p, ok := r.ProposeRule(s, nil, nil)
		if ok {
			t.Fatal("ProposeRule() ok = true, want false")
		}
		if p.Block != nil || p.TC != nil || p.Sig.Signer != 0 || len(p.Sig.Data) != 0 {
			t.Errorf("ProposeRule() on refusal = %+v, want zero Proposal", p)
		}
	})

	t.Run("refused when HighQC view exceeds State view", func(t *testing.T) {
		s := hotstuff.State{View: 4, HighQC: hotstuff.QuorumCert{View: 5}}
		p, ok := r.ProposeRule(s, nil, nil)
		if ok {
			t.Fatal("ProposeRule() ok = true, want false")
		}
		if p.Block != nil || p.TC != nil || p.Sig.Signer != 0 || len(p.Sig.Data) != 0 {
			t.Errorf("ProposeRule() on refusal = %+v, want zero Proposal", p)
		}
	})

	t.Run("nil commands accepted", func(t *testing.T) {
		s := hotstuff.State{View: 2, HighQC: hotstuff.QuorumCert{View: 1}}
		p, ok := r.ProposeRule(s, nil, nil)
		if !ok {
			t.Fatal("ProposeRule() ok = false, want true")
		}
		if len(p.Block.Cmds()) != 0 {
			t.Errorf("Cmds() = %v, want none", p.Block.Cmds())
		}
	})

	t.Run("empty commands accepted", func(t *testing.T) {
		s := hotstuff.State{View: 2, HighQC: hotstuff.QuorumCert{View: 1}}
		p, ok := r.ProposeRule(s, [][]byte{}, nil)
		if !ok {
			t.Fatal("ProposeRule() ok = false, want true")
		}
		if len(p.Block.Cmds()) != 0 {
			t.Errorf("Cmds() = %v, want none", p.Block.Cmds())
		}
	})
}

func TestChainLength(t *testing.T) {
	// ChainLength is the number of consecutive certified views a commit needs.
	if got := consensus.NewRules(1, blockchain.New()).ChainLength(); got != 3 {
		t.Errorf("ChainLength() = %d, want 3", got)
	}
}

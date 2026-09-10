package consensus

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// Timer policy shared by every harness: small enough to keep tests fast,
// spaced enough that Duration()'s growth is easy to reason about.
const (
	baseDuration  = 10 * time.Millisecond
	maxDuration   = 80 * time.Millisecond
	backoffFactor = 2.0
)

// harness wires one replica's Core to recording/deterministic test doubles.
type harness struct {
	core  *Core
	loop  *Loop
	tr    *fake.Transport
	clk   *fake.Clock
	store *blockchain.Store
	log   *hotstuff.MemLog
	dur   *ExponentialDuration
	cmds  *fake.Commands
	id    hotstuff.ID
	n     int
}

// newHarness builds replica id in a group of n, with a hand-driven clock and a
// recording transport. The Loop is wired as the core's EventSink, so a fired
// timer becomes a queued event Tick can pick up.
func newHarness(t *testing.T, id hotstuff.ID, n int) *harness {
	t.Helper()
	store := blockchain.New()
	tr := &fake.Transport{}
	clk := fake.NewClock(time.Unix(0, 0))
	log := hotstuff.NewMemLog()
	dur := NewViewDuration(baseDuration, maxDuration, backoffFactor)
	cmds := &fake.Commands{}
	// The queue is the root of the dependency graph: it exists before the core,
	// which is what breaks the cycle between the core and its transport.
	q := hotstuff.NewQueue(64)

	core := New(Config{
		ID:        id,
		N:         n,
		Rules:     NewRules(id, store),
		Store:     store,
		Crypto:    nocrypto.New(id, n),
		Transport: tr,
		Leader:    hotstuff.RoundRobin(n),
		Clock:     clk,
		Duration:  dur,
		Commands:  cmds,
		Executor:  log,
		Sink:      q,
	})
	loop := NewLoop(core, q)

	return &harness{core: core, loop: loop, tr: tr, clk: clk, store: store, log: log, dur: dur, cmds: cmds, id: id, n: n}
}

// proposalFor builds the proposal the leader of v would send: a block
// extending qc, proposed and signed by RoundRobin(n)(v).
func (h *harness) proposalFor(t *testing.T, v hotstuff.View, qc hotstuff.QuorumCert, tc *hotstuff.TimeoutCert, cmds [][]byte) hotstuff.Proposal {
	t.Helper()
	proposer := hotstuff.RoundRobin(h.n)(v)
	block := hotstuff.NewBlock(qc.BlockHash, v, proposer, qc, cmds)
	sig, err := nocrypto.New(proposer, h.n).Sign(block.Hash())
	if err != nil {
		t.Fatalf("sign proposal: %v", err)
	}
	return hotstuff.Proposal{Block: block, Sig: sig, TC: tc}
}

// voteFrom builds replica signer's vote for (view, blockHash).
func (h *harness) voteFrom(t *testing.T, signer hotstuff.ID, view hotstuff.View, bh hotstuff.Hash) hotstuff.PartialCert {
	t.Helper()
	sig, err := nocrypto.New(signer, h.n).Sign(hotstuff.VoteDigest(view, bh))
	if err != nil {
		t.Fatalf("sign vote: %v", err)
	}
	return hotstuff.PartialCert{View: view, BlockHash: bh, Sig: sig}
}

// timeoutFrom builds replica signer's timeout for view, carrying highQC.
func (h *harness) timeoutFrom(t *testing.T, signer hotstuff.ID, view hotstuff.View, highQC hotstuff.QuorumCert) hotstuff.TimeoutMsg {
	t.Helper()
	sig, err := nocrypto.New(signer, h.n).Sign(hotstuff.TimeoutDigest(view))
	if err != nil {
		t.Fatalf("sign timeout: %v", err)
	}
	return hotstuff.TimeoutMsg{View: view, Sig: sig, HighQC: highQC}
}

// qcFor builds a canonical QC over (view, blockHash) signed by a quorum.
func (h *harness) qcFor(t *testing.T, view hotstuff.View, bh hotstuff.Hash) hotstuff.QuorumCert {
	t.Helper()
	quorum := hotstuff.QuorumSize(h.n)
	sigs := make([]hotstuff.Signature, 0, quorum)
	for id := hotstuff.ID(1); int(id) <= quorum; id++ {
		sigs = append(sigs, h.voteFrom(t, id, view, bh).Sig)
	}
	return hotstuff.QuorumCert{View: view, BlockHash: bh, Sigs: canonical(sigs)}
}

// assertHighQCVerifies pins the invariant a certificate must satisfy: whatever
// QC the core adopts has to pass the replica's own verifier, or the proposal
// it justifies is rejected by every peer.
func (h *harness) assertHighQCVerifies(t *testing.T) {
	t.Helper()
	ver := hotstuff.NewVerifier(nocrypto.New(h.id, h.n), hotstuff.RoundRobin(h.n))
	if qc := h.core.State().HighQC; !ver.VerifyQC(qc) {
		t.Fatalf("HighQC{View:%d Hash:%x Sigs:%d} fails the replica's own VerifyQC", qc.View, qc.BlockHash[:4], len(qc.Sigs))
	}
}

// assertLockCoversLastVote pins the invariant behind the 3-chain's safety
// argument: a replica that voted for a block holds the block that block's QC
// certifies, and its lock is at least that block's own QC view — the
// grandparent whose certification the vote helps complete. The paper's lock is
// monotone, so it may already stand higher.
func (h *harness) assertLockCoversLastVote(t *testing.T) {
	t.Helper()
	if len(h.tr.Votes) == 0 {
		t.Fatal("no vote to check the lock against")
	}
	voted, ok := h.store.Get(h.tr.Votes[len(h.tr.Votes)-1].BlockHash)
	if !ok {
		t.Fatal("voted for a block the store does not hold")
	}
	parent, ok := h.store.Get(voted.QC().BlockHash)
	if !ok {
		t.Fatalf("voted for the block at view %d without holding the block its QC certifies", voted.View())
	}
	if got, want := h.core.State().LockedView, parent.QC().View; got < want {
		t.Fatalf("LockedView = %d after voting for the block at view %d, want at least its grandparent's view %d", got, voted.View(), want)
	}
}

// buildChain returns blocks for the given views, each extending the previous
// and carrying a QC for it, rooted at genesis. Proposer 1 throughout: the
// tests using it only ever inspect the commit/fetch path, never leadership.
func buildChain(views ...hotstuff.View) []*hotstuff.Block {
	blocks := make([]*hotstuff.Block, len(views))
	parent := hotstuff.Genesis()
	for i, v := range views {
		qc := hotstuff.QuorumCert{View: parent.View(), BlockHash: parent.Hash()}
		blocks[i] = hotstuff.NewBlock(parent.Hash(), v, 1, qc, nil)
		parent = blocks[i]
	}
	return blocks
}

// driveChain advances h through views 1..upTo via chained proposals and
// quorum votes: replica 1's own vote plus signers 2 and 3. It uses whichever
// proposal is due for v — externally built, or the one h's own core already
// self-proposed on entering a view it leads — and returns the accepted blocks.
func driveChain(t *testing.T, h *harness, upTo hotstuff.View) []*hotstuff.Block {
	t.Helper()
	leader := hotstuff.RoundRobin(h.n)
	qc := hotstuff.QuorumCert{BlockHash: hotstuff.GenesisHash()} // view 0
	blocks := make([]*hotstuff.Block, 0, upTo)

	for v := hotstuff.View(1); v <= upTo; v++ {
		var p hotstuff.Proposal
		if leader(v) == h.id {
			p = h.tr.Proposals[len(h.tr.Proposals)-1] // self-proposed on entering v
		} else {
			p = h.proposalFor(t, v, qc, nil, nil)
		}

		votesBefore := len(h.tr.Votes)
		h.core.Step(hotstuff.ProposeEvent{Proposal: p})
		if len(h.tr.Votes) != votesBefore+1 {
			t.Fatalf("driveChain: view %d: core did not vote for the chained proposal", v)
		}
		blocks = append(blocks, p.Block)

		bh := p.Block.Hash()
		own := h.tr.Votes[len(h.tr.Votes)-1]
		h.core.Step(hotstuff.VoteEvent{PartialCert: own})
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, v, bh)})
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, v, bh)})

		h.assertHighQCVerifies(t)
		h.assertLockCoversLastVote(t)
		qc = hotstuff.QuorumCert{View: v, BlockHash: bh}
	}
	return blocks
}

// harnessWithGap builds a 4-view chain, stores every block except those at
// withholdIdx, drives the core to view 4 and feeds the view-4 proposal so the
// commit gap is triggered.
func harnessWithGap(t *testing.T, withholdIdx ...int) (*harness, []*hotstuff.Block) {
	t.Helper()
	h := newHarness(t, 1, 4)
	h.core.Start()

	blocks := buildChain(1, 2, 3, 4)
	skip := map[int]bool{}
	for _, i := range withholdIdx {
		skip[i] = true
	}
	for i, b := range blocks {
		if !skip[i] {
			h.store.Put(b)
		}
	}

	h.core.view = 4 // put the core at view 4 without going through the chain
	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: blocks[3]}})
	return h, blocks
}

// --- The normal case ---

func TestFourChainedProposalsCommitBlock1(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	blocks := driveChain(t, h, 4)
	b1 := blocks[0]

	snap := h.log.Snapshot()
	if len(snap) != 1 || snap[0] != b1 {
		t.Fatalf("committed log = %v, want exactly [b1]", snap)
	}
	if got := h.core.State().CommittedView; got != 1 {
		t.Errorf("CommittedView = %d, want 1", got)
	}
	if got := h.core.State().HighQC.View; got != 4 {
		t.Errorf("HighQC.View = %d, want 4", got)
	}
}

func TestOneVotePerAcceptedProposal(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	blocks := driveChain(t, h, 4)
	if len(h.tr.Votes) != len(blocks) {
		t.Fatalf("Votes = %d entries, want one per accepted proposal (%d)", len(h.tr.Votes), len(blocks))
	}
	for i, b := range blocks {
		v := h.tr.Votes[i]
		if v.View != b.View() || v.BlockHash != b.Hash() {
			t.Errorf("vote %d = {View:%d Hash:%x}, want {View:%d Hash:%x}", i, v.View, v.BlockHash, b.View(), b.Hash())
		}
	}

	// feeding the last proposal again must not add a second vote
	last := hotstuff.Proposal{Block: blocks[len(blocks)-1]}
	before := len(h.tr.Votes)
	h.core.Step(hotstuff.ProposeEvent{Proposal: last})
	if len(h.tr.Votes) != before {
		t.Errorf("Votes grew from %d to %d on a duplicate proposal", before, len(h.tr.Votes))
	}
}

func TestLeaderProposesOnEnteringOwnView(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()
	cmds := [][]byte{[]byte("cmd-a"), []byte("cmd-b")}
	h.cmds.Batches = [][][]byte{cmds}

	blocks := driveChain(t, h, 3) // replica 1 leads view 4, so this makes it self-propose
	prev := blocks[len(blocks)-1]

	if len(h.tr.Proposals) != 1 {
		t.Fatalf("Proposals = %d entries, want 1", len(h.tr.Proposals))
	}
	p := h.tr.Proposals[0]
	if p.Block.View() != 4 {
		t.Errorf("Block.View() = %d, want 4", p.Block.View())
	}
	if p.Block.Proposer() != h.id {
		t.Errorf("Block.Proposer() = %d, want %d", p.Block.Proposer(), h.id)
	}
	if p.Block.Parent() != prev.Hash() {
		t.Errorf("Block.Parent() = %x, want %x", p.Block.Parent(), prev.Hash())
	}
	if p.Sig.Signer != h.id || len(p.Sig.Data) == 0 {
		t.Errorf("Sig = %+v, want signed by %d", p.Sig, h.id)
	}
	if p.TC != nil {
		t.Errorf("TC = %v, want nil: the QC alone justifies view 4 here", p.TC)
	}
	if _, ok := h.store.Get(p.Block.Hash()); !ok {
		t.Errorf("store does not hold the proposed block")
	}
	gotCmds := p.Block.Cmds()
	if len(gotCmds) != len(cmds) {
		t.Fatalf("Cmds() has %d entries, want %d", len(gotCmds), len(cmds))
	}
	for i := range cmds {
		if string(gotCmds[i]) != string(cmds[i]) {
			t.Errorf("Cmds()[%d] = %q, want %q", i, gotCmds[i], cmds[i])
		}
	}
}

// --- Vote accumulation ---

func TestVoteBeforeBlockFormsQC(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var bh hotstuff.Hash
	bh[0] = 0xAB
	quorum := hotstuff.QuorumSize(h.n)
	for id := hotstuff.ID(1); int(id) <= quorum; id++ {
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, id, 1, bh)})
	}

	if got := h.core.State().HighQC.View; got != 1 {
		t.Errorf("HighQC.View = %d, want 1", got)
	}
	if got := h.core.State().View; got != 2 {
		t.Errorf("View = %d, want 2", got)
	}
	if h.store.Len() != 1 { // genesis only
		t.Errorf("store.Len() = %d, want 1: the store must never be touched", h.store.Len())
	}
}

func TestDuplicateVoteCountedOnce(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var bh hotstuff.Hash
	bh[0] = 0x01
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 1, 1, bh)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, bh)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, bh)}) // repeat
	if got := h.core.State().View; got != 1 {
		t.Fatalf("View = %d, want still 1 after a repeated signer", got)
	}

	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, 1, bh)}) // missing distinct signer
	if got := h.core.State().View; got != 2 {
		t.Errorf("View = %d, want 2 once the third distinct signer votes", got)
	}
}

func TestSubQuorumVotesFormNothing(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var bh hotstuff.Hash
	bh[0] = 0x02
	quorum := hotstuff.QuorumSize(h.n)
	for id := hotstuff.ID(1); int(id) < quorum; id++ { // one short
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, id, 1, bh)})
	}

	if h.core.State().HighQC.View != 0 || h.core.State().View != 1 {
		t.Errorf("state advanced on a sub-quorum: HighQC.View=%d View=%d", h.core.State().HighQC.View, h.core.State().View)
	}
}

func TestVotesForCertifiedViewAreDropped(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var bh hotstuff.Hash
	bh[0] = 0x03
	quorum := hotstuff.QuorumSize(h.n)
	for id := hotstuff.ID(1); int(id) <= quorum; id++ {
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, id, 1, bh)})
	}
	if len(h.core.votes) != 0 {
		t.Fatalf("votes not pruned after the QC formed: %d entries", len(h.core.votes))
	}

	var other hotstuff.Hash
	other[0] = 0x04
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 1, 1, other)}) // same certified view, different block
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 1, 1, bh)})    // the certified block itself

	if len(h.core.votes) != 0 {
		t.Errorf("votes has %d entries, want 0: votes at or below a certified view are dropped", len(h.core.votes))
	}
	if got := h.core.State().View; got != 2 {
		t.Errorf("View = %d, want unchanged 2", got)
	}
}

func TestVotesForDifferentBlocksDoNotMix(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var a, b hotstuff.Hash
	a[0], b[0] = 0x0A, 0x0B
	// quorum(4) - 1 = 2 votes for each of two competing blocks in view 1,
	// from disjoint signers: nobody votes twice in a view.
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 1, 1, a)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, a)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, 1, b)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 4, 1, b)})

	if got := h.core.State().View; got != 1 {
		t.Fatalf("View = %d, want still 1", got)
	}
	if n := len(h.core.votes); n != 2 {
		t.Errorf("votes has %d entries, want 2 separate blocks", n)
	}
}

func TestSignerVotesOncePerView(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var a, b hotstuff.Hash
	a[0], b[0] = 0x0A, 0x0B
	// An honest replica votes at most once per view, so a faulty one that
	// equivocates buys nothing — and opens no second bucket, which is what
	// keeps the accumulator bounded against fabricated block hashes.
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, a)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, b)})

	if n := len(h.core.votes); n != 1 {
		t.Errorf("votes has %d entries, want 1: a signer's second vote in a view is ignored", n)
	}
	if n := len(h.core.votes[voteKey{view: 1, hash: a}]); n != 1 {
		t.Errorf("the first bucket holds %d signatures, want 1", n)
	}
}

func TestMixedViewVotesDoNotFormAQC(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	bh := buildChain(1)[0].Hash()
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 1, 1, bh)})
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 2, 1, bh)})
	// A faulty replica claims a different view for the block two honest
	// replicas just voted for. The three signatures cover two digests, so they
	// are not a quorum for either.
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, 2, bh)})

	if got := h.core.State().HighQC.View; got != 0 {
		t.Errorf("HighQC.View = %d, want 0: votes over two digests cannot certify", got)
	}
	h.assertHighQCVerifies(t)

	// The honest third vote completes the quorum the faulty one could not.
	h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, 1, bh)})
	if got := h.core.State().HighQC.View; got != 1 {
		t.Errorf("HighQC.View = %d, want 1", got)
	}
	h.assertHighQCVerifies(t)
}

// --- Locking ---

func TestLockViolationBlocksVoteButRaisesHighQC(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()
	h.core.lockedView = 5 // simulate a replica whose lock is already far ahead

	// A QC newer than our highQC(0) yet still below the lock(5).
	qc := hotstuff.QuorumCert{View: 2, BlockHash: hotstuff.GenesisHash()}
	block := hotstuff.NewBlock(hotstuff.Hash{0x99}, 1, 2, qc, nil)

	votesBefore := len(h.tr.Votes)
	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: block}})

	if len(h.tr.Votes) != votesBefore {
		t.Errorf("a vote was emitted despite the lock violation")
	}
	if h.core.lastVotedView != 0 {
		t.Errorf("lastVotedView = %d, want unchanged 0", h.core.lastVotedView)
	}
	if got := h.core.State().HighQC.View; got != 2 {
		t.Errorf("HighQC.View = %d, want 2: a newer QC is adopted even under a lock violation", got)
	}
}

func TestLockUpdatesTwoCertsBack(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	driveChain(t, h, 3)
	if got := h.core.State().LockedView; got != 1 {
		t.Errorf("LockedView = %d, want 1", got)
	}
}

// TestAbsentCertifiedBlockBlocksTheVote is the inverse of what this test used
// to pin. The lock cannot be raised to a block the store lacks, so the vote
// that would help certify the proposal must not be cast either: casting it
// would put this replica in a certifying quorum with a stale lock.
func TestAbsentCertifiedBlockBlocksTheVote(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var missing hotstuff.Hash
	missing[0] = 0x77
	badQC := hotstuff.QuorumCert{View: 1, BlockHash: missing} // never stored
	block := hotstuff.NewBlock(missing, 2, 3, badQC, nil)

	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: block}})

	if n := len(h.tr.Votes); n != 0 {
		t.Errorf("Votes = %d, want 0", n)
	}
	if got := h.core.State().LockedView; got != 0 {
		t.Errorf("LockedView = %d, want unchanged 0", got)
	}
}

// TestGapSkipsOneVoteThenResumes is the liveness cost of that rule, made
// explicit: a replica that missed a block cannot vote for the proposal
// certifying it, asks for it, and is voting again by the next view.
func TestGapSkipsOneVoteThenResumes(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	blocks := buildChain(1, 2, 3, 4)
	b2, b3, b4 := blocks[1], blocks[2], blocks[3]

	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: blocks[0]}})
	h.assertLockCoversLastVote(t)

	// b2 never arrives, so b3 certifies a block this replica does not hold.
	votes := len(h.tr.Votes)
	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: b3}})
	if len(h.tr.Votes) != votes {
		t.Fatal("voted for a block whose certified parent is absent")
	}
	if got := h.core.State().LockedView; got != 0 {
		t.Errorf("LockedView = %d, want 0: the lock could not move, which is why the vote was skipped", got)
	}
	if len(h.tr.Fetches) == 0 || h.tr.Fetches[0] != b2.Hash() {
		t.Fatalf("Fetches = %x, want a request for the missing %x", h.tr.Fetches, b2.Hash())
	}

	h.core.Step(hotstuff.FetchedEvent{Block: b2})
	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: b4}})
	if len(h.tr.Votes) != votes+1 {
		t.Fatalf("Votes = %d, want the replica voting again in the next view", len(h.tr.Votes))
	}
	h.assertLockCoversLastVote(t)
	if got := h.core.State().LockedView; got != 2 {
		t.Errorf("LockedView = %d, want 2: b4's QC certifies b3, whose QC certifies b2", got)
	}
}

// --- Fetching and the commit gap ---

func TestMissingAncestorFetchesOnce(t *testing.T) {
	h, blocks := harnessWithGap(t, 0) // b1 withheld
	b1 := blocks[0]

	// the commit check runs again for the same gap
	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: blocks[3]}})

	if len(h.tr.Fetches) != 1 || h.tr.Fetches[0] != b1.Hash() {
		t.Fatalf("Fetches = %x, want exactly one entry for %x", h.tr.Fetches, b1.Hash())
	}
	if _, ok := h.core.fetching[b1.Hash()]; !ok {
		t.Errorf("fetching does not hold %x", b1.Hash())
	}
}

func TestFetchedEventCompletesTheCommit(t *testing.T) {
	h, blocks := harnessWithGap(t, 0)
	b1 := blocks[0]

	h.core.Step(hotstuff.FetchedEvent{Block: b1})

	if _, ok := h.core.fetching[b1.Hash()]; ok {
		t.Errorf("fetching still holds %x", b1.Hash())
	}
	if _, ok := h.store.Get(b1.Hash()); !ok {
		t.Errorf("store does not hold the fetched block")
	}
	if h.log.Len() == 0 {
		t.Errorf("commit log is empty, want the parked commit to have completed")
	}
	if got := h.core.State().CommittedView; got != 1 {
		t.Errorf("CommittedView = %d, want 1", got)
	}
}

func TestSecondGapFetchesAgain(t *testing.T) {
	h, blocks := harnessWithGap(t, 0, 1) // b1 and b2 both withheld
	b1, b2 := blocks[0], blocks[1]

	if len(h.tr.Fetches) != 1 || h.tr.Fetches[0] != b2.Hash() {
		t.Fatalf("first Fetches = %x, want [%x] (the nearer gap)", h.tr.Fetches, b2.Hash())
	}

	h.core.Step(hotstuff.FetchedEvent{Block: b2})
	if len(h.tr.Fetches) != 2 || h.tr.Fetches[1] != b1.Hash() {
		t.Fatalf("second Fetches = %x, want to also ask for %x", h.tr.Fetches, b1.Hash())
	}
	if h.log.Len() != 0 {
		t.Fatalf("commit completed early, log has %d entries", h.log.Len())
	}

	h.core.Step(hotstuff.FetchedEvent{Block: b1})
	if h.log.Len() == 0 {
		t.Errorf("commit did not complete once both ancestors arrived")
	}
	if got := h.core.State().CommittedView; got != 1 {
		t.Errorf("CommittedView = %d, want 1", got)
	}
}

// TestUnansweredFetchIsRetried pins the recovery behind a failed backfill:
// nothing answers the first request, and the gap is asked for again once the
// view has moved on far enough that no answer can still be in flight.
func TestUnansweredFetchIsRetried(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	blocks := buildChain(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	for _, b := range blocks[1:] { // b1 withheld, and no responder ever has it
		h.store.Put(b)
	}
	b1 := blocks[0]

	h.core.view = 4
	h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: blocks[3]}})
	if len(h.tr.Fetches) != 1 || h.tr.Fetches[0] != b1.Hash() {
		t.Fatalf("Fetches = %x, want one request for %x", h.tr.Fetches, b1.Hash())
	}
	issuedAt := h.core.fetching[b1.Hash()]

	// Every later proposal re-runs the commit check and finds the same gap,
	// but the request may not repeat before the retry threshold.
	for _, b := range blocks[4:] {
		at := h.core.State().View
		h.core.Step(hotstuff.ProposeEvent{Proposal: hotstuff.Proposal{Block: b}})
		if len(h.tr.Fetches) > 1 {
			if at < issuedAt+fetchRetryViews {
				t.Fatalf("gap re-requested at view %d, want no earlier than %d", at, issuedAt+fetchRetryViews)
			}
			break
		}
	}
	if len(h.tr.Fetches) != 2 || h.tr.Fetches[1] != b1.Hash() {
		t.Fatalf("Fetches = %x, want the unanswered gap re-requested", h.tr.Fetches)
	}

	// The parked commit still completes the moment a responder finally has it.
	h.core.Step(hotstuff.FetchedEvent{Block: b1})
	if h.log.Len() == 0 {
		t.Error("commit log is empty, want the parked commit to complete once the gap filled")
	}
	if got := h.core.State().CommittedView; got == 0 {
		t.Error("CommittedView = 0, want the completed commit to have moved it")
	}
}

// --- Pruning ---

func TestAccumulatorsStayBounded(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	const views = 120
	for v := hotstuff.View(1); v <= views; v++ {
		if v%5 == 0 {
			// advance via a timeout quorum now and then, so timeouts is exercised too.
			for _, signer := range []hotstuff.ID{2, 3, 4} {
				h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, signer, v, h.core.State().HighQC)})
			}
			continue
		}
		var bh hotstuff.Hash
		bh[0], bh[1] = byte(v), byte(v>>8)
		for _, signer := range []hotstuff.ID{1, 2, 3} {
			h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, signer, v, bh)})
		}
	}

	// Unbounded accumulation is the failure mode this pins: each map must stay
	// small no matter how many views go by.
	if n := len(h.core.votes); n >= 5 {
		t.Errorf("votes has %d entries, want < 5", n)
	}
	if n := len(h.core.timeouts); n >= 5 {
		t.Errorf("timeouts has %d entries, want < 5", n)
	}
	if n := len(h.core.fetching); n >= 5 {
		t.Errorf("fetching has %d entries, want < 5", n)
	}

	// The same bound has to hold against a sender following no protocol at
	// all: a flood of votes and timeouts for far-off views, each naming a
	// block nobody proposed. Every one passes edge verification, which is
	// state-free by design and never sees a view.
	const junk = 20_000
	votes, timeouts := len(h.core.votes), len(h.core.timeouts)
	for i := range junk {
		v := hotstuff.View(1_000_000 + i)
		var bh hotstuff.Hash
		bh[0], bh[1], bh[2] = byte(i), byte(i>>8), byte(i>>16)
		h.core.Step(hotstuff.VoteEvent{PartialCert: h.voteFrom(t, 3, v, bh)})
		h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 3, v, h.core.State().HighQC)})
	}
	if n := len(h.core.votes); n != votes {
		t.Errorf("votes grew from %d to %d entries under %d junk votes", votes, n, junk)
	}
	if n := len(h.core.timeouts); n != timeouts {
		t.Errorf("timeouts grew from %d to %d entries under %d junk timeouts", timeouts, n, junk)
	}
	if n := len(h.core.voters); n >= 5 {
		t.Errorf("voters has %d entries, want < 5", n)
	}
}

// TestFarFutureTimeoutStillCatchesUp checks that bounding the accumulators
// left the catch-up path alone: a timeout's QC is adopted however far ahead
// the timeout itself is, which is how a lagging replica learns the chain has
// moved on without any NewView message in the protocol.
func TestFarFutureTimeoutStillCatchesUp(t *testing.T) {
	h := newHarness(t, 1, 4)
	h.core.Start()

	var bh hotstuff.Hash
	bh[0] = 0x11
	qc := h.qcFor(t, 500, bh)
	h.core.Step(hotstuff.TimeoutEvent{TimeoutMsg: h.timeoutFrom(t, 2, 501, qc)})

	if got := h.core.State().HighQC.View; got != 500 {
		t.Errorf("HighQC.View = %d, want 500: a timeout's QC is adopted however far ahead it is", got)
	}
	if n := len(h.core.timeouts); n != 0 {
		t.Errorf("timeouts has %d entries, want 0: the signature itself is far past the lead bound", n)
	}
	// And the QC it brought is enough to enter the view it certifies.
	h.core.Step(hotstuff.ProposeEvent{Proposal: h.proposalFor(t, 501, qc, nil, nil)})
	if got := h.core.State().View; got != 501 {
		t.Errorf("View = %d, want 501", got)
	}
}

package diem

import (
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
)

// The tests here cover what Core decides from protocol state — which round it
// is in, who leads that round. What a message can be judged on by itself is
// authenticated at the edge, and diem/verify_test.go covers that half.

// coreFixture is replica 2 in a group of 4, started and sitting in round 1.
// Replica 1 leads round 1, so this replica is a voter; it leads rounds 2 and 3,
// so it is also the collector for round 1's votes.
type coreFixture struct {
	core   *Core
	ledger *MemLedger
	net    *recordNet
}

func newCoreFixture(t *testing.T) *coreFixture {
	t.Helper()
	f := &coreFixture{ledger: NewMemLedger(), net: &recordNet{}}
	ids := []uint32{1, 2, 3, 4}
	f.core = New(Config{
		ID:           2,
		Validators:   ids,
		Ledger:       f.ledger,
		Transactions: NewFIFOPool(16, 2).GetTransactions,
		Crypto:       newTestSigner(testN),
		Transport:    f.net,
		Clock:        newFakeClock(),
		Backoff:      NewBackoff(100*time.Millisecond, time.Second, 2),
		Lock:         new(sync.Mutex),
	})
	f.core.Start()
	if got := f.core.State().Round; got != 1 {
		t.Fatalf("started in round %d, want 1", got)
	}
	if len(f.net.proposals) != 0 {
		t.Fatal("replica 2 proposed in round 1, which replica 1 leads")
	}
	return f
}

// proposal is a well-formed round-1 proposal from replica 1 over genesis.
func proposal(from uint32, author uint32, round uint64) *diempb.ProposalMsg {
	b := NewBlock(author, round, [][]byte{{0xaa}}, genesisQC)
	return diempb.ProposalMsg_builder{
		Block:        b,
		HighCommitQc: genesisQC,
		Sender:       from,
		Sig:          signAs(from, b.GetId()),
	}.Build()
}

// TestStoppedCoreIgnoresInput: the network can deliver after the replica has
// stopped its core. Acting on that would send a vote, or re-arm the timer the
// stop disarmed.
func TestStoppedCoreIgnoresInput(t *testing.T) {
	f := newCoreFixture(t)
	f.core.Stop()

	f.core.OnProposal(proposal(1, 1, 1))
	for _, from := range []uint32{1, 3, 4} { // a quorum
		f.core.OnTimeout(timeoutFrom(t, from))
	}
	if len(f.net.votes) != 0 || len(f.net.timeouts) != 0 {
		t.Fatalf("a stopped core sent %d votes and %d timeouts, want none", len(f.net.votes), len(f.net.timeouts))
	}
	if n := len(f.core.pacemaker.clock.(*fakeClock).pending); n != 0 {
		t.Fatalf("a stopped core armed %d timers, want none", n)
	}
}

func TestCoreVotesForValidProposal(t *testing.T) {
	f := newCoreFixture(t)
	f.core.OnProposal(proposal(1, 1, 1))

	if len(f.net.votes) != 1 {
		t.Fatalf("sent %d votes for a valid proposal, want 1", len(f.net.votes))
	}
	// The vote goes to the leader of the next round, the only replica that can
	// build a certificate out of it.
	if f.net.voteTo[0] != 2 {
		t.Errorf("voted to replica %d, want the round-2 leader (2)", f.net.voteTo[0])
	}
}

// TestCoreRejectsProposals covers the core's half of the split: the checks that
// read protocol state. Everything a message can be judged on by itself is the
// Verifier's, and diem/verify_test.go holds those cases.
func TestCoreRejectsProposals(t *testing.T) {
	tests := []struct {
		name string
		msg  func() *diempb.ProposalMsg
	}{
		{"sender is not the round's leader", func() *diempb.ProposalMsg {
			return proposal(3, 3, 1)
		}},
		{"sender and author disagree", func() *diempb.ProposalMsg {
			p := proposal(3, 1, 1)
			return p
		}},
		{"round is not the round this replica is in", func() *diempb.ProposalMsg {
			return proposal(1, 1, 7)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newCoreFixture(t)
			f.core.OnProposal(tc.msg())
			if len(f.net.votes) != 0 {
				t.Fatalf("voted for a proposal that should have been dropped")
			}
		})
	}
}

// voteFor builds replica from's honest vote for b, by running a real Safety
// over a ledger that has speculated the block.
func voteFor(t *testing.T, from uint32, b *diempb.Block) *diempb.VoteMsg {
	t.Helper()
	ledger := NewMemLedger()
	ledger.Speculate(b)
	signer := newTestSigner(testN)
	tree := NewBlockTree(from, testQuorum, ledger, signer)
	v := NewSafety(from, NewVerifier(signer, testQuorum), signer, ledger, tree).MakeVote(b, nil)
	if v == nil {
		t.Fatalf("replica %d refused to vote for round %d", from, b.GetRound())
	}
	return v
}

// TestCoreFormsQCFromQuorum is the control for the rejection test below: an
// honest quorum must produce exactly one certificate and one proposal.
func TestCoreFormsQCFromQuorum(t *testing.T) {
	f := newCoreFixture(t)
	p := proposal(1, 1, 1)
	f.core.OnProposal(p)

	for _, from := range []uint32{1, 3, 4} {
		f.core.OnVote(voteFor(t, from, p.GetBlock()))
	}
	if got := f.core.State().Round; got != 2 {
		t.Fatalf("round %d after a quorum of votes, want 2", got)
	}
	if len(f.net.proposals) != 1 {
		t.Fatalf("emitted %d proposals as the round-2 leader, want 1", len(f.net.proposals))
	}
}

// TestCoreProposesOncePerRound is the late-vote case: a leader that entered
// its round on a TC and proposed must not propose again when the votes for the
// round it skipped complete a QC after all.
func TestCoreProposesOncePerRound(t *testing.T) {
	f := newCoreFixture(t)
	p := proposal(1, 1, 1)
	f.core.OnProposal(p)

	for _, from := range []uint32{1, 3, 4} {
		f.core.OnTimeout(timeoutFrom(t, from))
	}
	if got := f.core.State().Round; got != 2 {
		t.Fatalf("setup: round %d after a TC for round 1, want 2", got)
	}
	if len(f.net.proposals) != 1 {
		t.Fatalf("setup: emitted %d proposals on entering round 2, want 1", len(f.net.proposals))
	}

	for _, from := range []uint32{1, 3, 4} {
		f.core.OnVote(voteFor(t, from, p.GetBlock()))
	}
	if got := f.core.State().HighQCRound; got != 1 {
		t.Fatalf("setup: high QC round %d after the late votes, want 1", got)
	}
	if len(f.net.proposals) != 1 {
		t.Fatalf("emitted %d proposals for round 2, want 1", len(f.net.proposals))
	}
}

// timeoutFrom builds replica from's honest timeout for round 1 over genesis.
func timeoutFrom(t *testing.T, from uint32) *diempb.TimeoutMsg {
	t.Helper()
	ledger := NewMemLedger()
	signer := newTestSigner(testN)
	tree := NewBlockTree(from, testQuorum, ledger, signer)
	info := NewSafety(from, NewVerifier(signer, testQuorum), signer, ledger, tree).MakeTimeout(1, genesisQC, nil)
	if info == nil {
		t.Fatalf("replica %d refused to time out round 1", from)
	}
	return diempb.TimeoutMsg_builder{TmoInfo: info, HighCommitQc: genesisQC}.Build()
}

// TestCoreAmplifiesTimeouts is the control: f+1 honest timeouts make this
// replica give up on the round too.
func TestCoreAmplifiesTimeouts(t *testing.T) {
	f := newCoreFixture(t)
	for _, from := range []uint32{1, 3} { // f+1 = 2 distinct senders
		f.core.OnTimeout(timeoutFrom(t, from))
	}
	if len(f.net.timeouts) != 1 {
		t.Fatalf("broadcast %d timeouts after f+1 remote ones, want 1", len(f.net.timeouts))
	}
}

// TestCoreIgnoresStaleTimer covers the guard on the local timer: a callback
// that fired while another call moved the round on must not make the replica
// give up on the round it is in now.
func TestCoreIgnoresStaleTimer(t *testing.T) {
	f := newCoreFixture(t)
	clock := f.core.pacemaker.clock.(*fakeClock)
	stale := clock.take(time.Second)
	if stale == nil {
		t.Fatal("setup: no round-1 timer armed")
	}

	for _, from := range []uint32{1, 3, 4} { // a quorum: round 2 on a TC
		f.core.OnTimeout(timeoutFrom(t, from))
	}
	if got := f.core.State().Round; got != 2 {
		t.Fatalf("setup: in round %d, want 2", got)
	}
	sent := len(f.net.timeouts)
	stale()
	if len(f.net.timeouts) != sent {
		t.Fatal("timed out on a stale timer callback")
	}
	clock.take(time.Second)()
	if len(f.net.timeouts) != sent+1 {
		t.Fatalf("broadcast %d timeouts for the armed timer, want 1", len(f.net.timeouts)-sent)
	}
}

// TestCoreIgnoresTimerRearmedInSameRound is the stale callback the round cannot
// tell apart: the timer fires, then f+1 remote timeouts re-arm the same round
// before its callback gets the lock.
func TestCoreIgnoresTimerRearmedInSameRound(t *testing.T) {
	f := newCoreFixture(t)
	stale := f.core.pacemaker.clock.(*fakeClock).take(time.Second)
	if stale == nil {
		t.Fatal("setup: no round-1 timer armed")
	}

	for _, from := range []uint32{1, 3} { // f+1 = 2 distinct senders
		f.core.OnTimeout(timeoutFrom(t, from))
	}
	if len(f.net.timeouts) != 1 {
		t.Fatalf("setup: broadcast %d timeouts after f+1 remote ones, want 1", len(f.net.timeouts))
	}

	stale()
	if len(f.net.timeouts) != 1 {
		t.Fatalf("broadcast %d timeouts after a disarmed timer's callback, want 1", len(f.net.timeouts))
	}
}

func TestCoreStopDisarmsTimer(t *testing.T) {
	clock := newFakeClock()
	net := &recordNet{}
	core := New(Config{
		ID:           1,
		Validators:   []uint32{1, 2, 3, 4},
		Ledger:       NewMemLedger(),
		Transactions: NewFIFOPool(16, 2).GetTransactions,
		Crypto:       newTestSigner(testN),
		Transport:    net,
		Clock:        clock,
		Backoff:      NewBackoff(100*time.Millisecond, time.Second, 2),
		Lock:         new(sync.Mutex),
	})
	core.Start()
	core.Stop()
	clock.Advance(time.Second)
	if len(net.timeouts) != 0 {
		t.Fatalf("a stopped core broadcast %d timeouts", len(net.timeouts))
	}
}

// fabricatedVote is what a Byzantine sender can put on the wire unaided: an
// arbitrary VoteInfo, its hash bound into a LedgerCommitInfo, and its own valid
// signature over that pair. Nothing in the message ties the round it claims to
// anything else.
func fabricatedVote(from uint32, round uint64) *diempb.VoteMsg {
	vi := voteInfo(hashOf(byte(round), byte(round>>8)), round, nil, 0)
	commit := commitInfo(nil, vi)
	return diempb.VoteMsg_builder{
		VoteInfo:         vi,
		LedgerCommitInfo: commit,
		Sender:           from,
		Sig:              signAs(from, commit.Digest()),
	}.Build()
}

// TestCoreBoundsVoteAccumulation is the accumulator bound. BlockTree.votes is
// keyed on the LedgerCommitInfo digest and a sender picks that freely, so every
// fabricated vote opens a bucket of its own. Pruning is no answer: it only runs
// on a commit, and these votes can never reach a quorum to produce one.
func TestCoreBoundsVoteAccumulation(t *testing.T) {
	f := newCoreFixture(t)
	v := newTestVerifier()

	const votes = 10000
	for r := uint64(1); r <= votes; r++ {
		m := fabricatedVote(1, r)
		if !v.VerifyVote(m) {
			t.Fatalf("setup: the fabricated vote for round %d must pass the edge", r)
		}
		f.core.OnVote(m)
	}
	if got := f.core.State().Round; got != 1 {
		t.Fatalf("round moved to %d on votes that can never form a quorum", got)
	}
	if got, want := len(f.core.tree.votes), maxRoundLead+1; got > want {
		t.Errorf("%d vote buckets after %d fabricated rounds, want at most %d", got, votes, want)
	}
}

// TestCoreDropsVotesForPastRounds stalls the replica in a late round and checks
// that only the previous and current rounds still open vote buckets.
func TestCoreDropsVotesForPastRounds(t *testing.T) {
	f := newCoreFixture(t)
	f.core.pacemaker.AdvanceRoundTC(makeTC(9))
	if got := f.core.State().Round; got != 10 {
		t.Fatalf("setup: round %d, want 10", got)
	}
	for r := uint64(1); r <= 8; r++ {
		f.core.OnVote(fabricatedVote(1, r))
	}
	if got := len(f.core.tree.votes); got != 0 {
		t.Fatalf("%d vote buckets for rounds below the previous one, want 0", got)
	}
	f.core.OnVote(fabricatedVote(1, 9))
	if got := len(f.core.tree.votes); got != 1 {
		t.Fatalf("%d vote buckets after a vote for the previous round, want 1", got)
	}
}

func TestNewRejectsHistoryShorterThanReputationWalk(t *testing.T) {
	ledger := NewMemLedger()
	ledger.History = defaultWindowSize
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted a ledger that forgets blocks the reputation walk reads")
		}
	}()
	New(Config{ID: 1, Validators: []uint32{1, 2, 3, 4}, Ledger: ledger})
}

// TestCoreIgnoresForgedGenesisCommit replays the attack end to end: a valid
// timeout re-wrapped around a forged round-0 commit certificate. No signature
// covers a timeout's high_commit_qc, so only the Verifier stands between it and
// a commit of a block no quorum ever certified.
func TestCoreIgnoresForgedGenesisCommit(t *testing.T) {
	f := newCoreFixture(t)
	v := NewVerifier(newTestSigner(testN), testQuorum)
	p := proposal(1, 1, 1)
	f.core.OnProposal(p)

	m := timeoutFrom(t, 3)
	m.SetHighCommitQc(forgedGenesisQC(p.GetBlock().GetId()))
	if v.VerifyTimeout(m) {
		f.core.OnTimeout(m)
	}
	if _, ok := f.ledger.CommittedBlock(p.GetBlock().GetId()); ok {
		t.Fatal("committed the round-1 block on a forged genesis certificate")
	}
}

package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// The tests here cover what Core decides from protocol state — which round it
// is in, who leads that round. What a message can be judged on by itself is
// authenticated at the edge, and diem/verify_test.go covers that half.

// coreFixture is replica 2 in a group of 4, started and sitting in round 1.
// Replica 1 leads round 1, so this replica is a voter; it leads rounds 2 and 3,
// so it is also the collector for round 1's votes.
type coreFixture struct {
	core   *Core
	net    *recordNet
	events *[]Event
}

func newCoreFixture(t *testing.T) *coreFixture {
	t.Helper()
	f := &coreFixture{net: &recordNet{}, events: new([]Event)}
	ids := []ID{1, 2, 3, 4}
	f.core = New(Config{
		ID:           2,
		Validators:   ids,
		Ledger:       NewMemLedger(),
		Transactions: NewFIFOPool(16, 2).GetTransactions,
		Crypto:       nocrypto.New(2, testN),
		Transport:    f.net,
		Clock:        fake.NewClock(time.Unix(0, 0)),
		Duration:     hotstuff.NewDuration(100*time.Millisecond, time.Second, 2),
		Sink:         recordSink(f.events),
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
func proposal(from ID, author ID, round Round) *ProposalMsg {
	b := NewBlock(author, round, [][]byte{{0xaa}}, genesisQC)
	return &ProposalMsg{
		Block:        b,
		HighCommitQC: genesisQC,
		Sender:       from,
		Sig:          signAs(from, b.ID()),
	}
}

func TestCoreVotesForValidProposal(t *testing.T) {
	f := newCoreFixture(t)
	f.core.Step(ProposalEvent{Msg: proposal(1, 1, 1)})

	if len(f.net.votes) != 1 {
		t.Fatalf("sent %d votes for a valid proposal, want 1", len(f.net.votes))
	}
	// The vote goes to the leader of the next round, the only replica that can
	// build a certificate out of it.
	if f.net.voteTo[0] != 2 {
		t.Errorf("voted to replica %d, want the round-2 leader (2)", f.net.voteTo[0])
	}
}

// TestCoreRejectsProposals covers the loop's half of the split: the checks that
// read protocol state. Everything a message can be judged on by itself is the
// Verifier's, and diem/verify_test.go holds those cases.
func TestCoreRejectsProposals(t *testing.T) {
	tests := []struct {
		name string
		msg  func() *ProposalMsg
	}{
		{"sender is not the round's leader", func() *ProposalMsg {
			return proposal(3, 3, 1)
		}},
		{"sender and author disagree", func() *ProposalMsg {
			p := proposal(3, 1, 1)
			return p
		}},
		{"round is not the round this replica is in", func() *ProposalMsg {
			return proposal(1, 1, 7)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newCoreFixture(t)
			f.core.Step(ProposalEvent{Msg: tc.msg()})
			if len(f.net.votes) != 0 {
				t.Fatalf("voted for a proposal that should have been dropped")
			}
		})
	}
}

// voteFor builds replica from's honest vote for b, by running a real Safety
// over a ledger that has speculated the block.
func voteFor(t *testing.T, from ID, b *Block) *VoteMsg {
	t.Helper()
	ledger := NewMemLedger()
	ledger.Speculate(b)
	signer := nocrypto.New(from, testN)
	tree := NewBlockTree(from, testQuorum, ledger, signer)
	v := NewSafety(from, NewVerifier(signer, testQuorum), signer, ledger, tree).MakeVote(b, nil)
	if v == nil {
		t.Fatalf("replica %d refused to vote for round %d", from, b.Round)
	}
	return v
}

// TestCoreFormsQCFromQuorum is the control for the rejection test below: an
// honest quorum must produce exactly one certificate and one proposal.
func TestCoreFormsQCFromQuorum(t *testing.T) {
	f := newCoreFixture(t)
	p := proposal(1, 1, 1)
	f.core.Step(ProposalEvent{Msg: p})

	for _, from := range []ID{1, 3, 4} {
		f.core.Step(VoteEvent{Msg: voteFor(t, from, p.Block)})
	}
	if got := f.core.State().Round; got != 2 {
		t.Fatalf("round %d after a quorum of votes, want 2", got)
	}
	if len(f.net.proposals) != 1 {
		t.Fatalf("emitted %d proposals as the round-2 leader, want 1", len(f.net.proposals))
	}
}

// timeoutFrom builds replica from's honest timeout for round 1 over genesis.
func timeoutFrom(t *testing.T, from ID) *TimeoutMsg {
	t.Helper()
	ledger := NewMemLedger()
	signer := nocrypto.New(from, testN)
	tree := NewBlockTree(from, testQuorum, ledger, signer)
	info := NewSafety(from, NewVerifier(signer, testQuorum), signer, ledger, tree).MakeTimeout(1, genesisQC, nil)
	if info == nil {
		t.Fatalf("replica %d refused to time out round 1", from)
	}
	return &TimeoutMsg{TmoInfo: *info, HighCommitQC: genesisQC}
}

// TestCoreAmplifiesTimeouts is the control: f+1 honest timeouts make this
// replica give up on the round too.
func TestCoreAmplifiesTimeouts(t *testing.T) {
	f := newCoreFixture(t)
	for _, from := range []ID{1, 3} { // f+1 = 2 distinct senders
		f.core.Step(TimeoutEvent{Msg: timeoutFrom(t, from)})
	}
	if len(f.net.timeouts) != 1 {
		t.Fatalf("broadcast %d timeouts after f+1 remote ones, want 1", len(f.net.timeouts))
	}
}

// TestCoreIgnoresStaleRoundTimer covers the guard on the local timer: a
// callback enqueued for a round that has since been left behind must not make
// the replica give up on the round it is in now.
func TestCoreIgnoresStaleRoundTimer(t *testing.T) {
	f := newCoreFixture(t)
	f.core.Step(LocalTimeoutEvent{Round: 0})
	if len(f.net.timeouts) != 0 {
		t.Fatal("timed out on a stale timer event")
	}
	f.core.Step(LocalTimeoutEvent{Round: 1})
	if len(f.net.timeouts) != 1 {
		t.Fatalf("broadcast %d timeouts for the current round, want 1", len(f.net.timeouts))
	}
}

func TestCoreStopDisarmsTimer(t *testing.T) {
	clock := fake.NewClock(time.Unix(0, 0))
	var events []Event
	core := New(Config{
		ID:           1,
		Validators:   []ID{1, 2, 3, 4},
		Ledger:       NewMemLedger(),
		Transactions: NewFIFOPool(16, 2).GetTransactions,
		Crypto:       nocrypto.New(1, testN),
		Transport:    &recordNet{},
		Clock:        clock,
		Duration:     hotstuff.NewDuration(100*time.Millisecond, time.Second, 2),
		Sink:         recordSink(&events),
	})
	core.Start()
	core.Stop()
	clock.Advance(time.Second)
	if len(events) != 0 {
		t.Fatalf("a stopped core pushed %d timer events", len(events))
	}
}

func TestQueueDeliversEvents(t *testing.T) {
	q := NewQueue(2)
	q.Push(LocalTimeoutEvent{Round: 3})
	e, ok := <-q
	if !ok {
		t.Fatal("queue closed")
	}
	lt, ok := e.(LocalTimeoutEvent)
	if !ok || lt.Round != 3 {
		t.Fatalf("received %#v, want LocalTimeoutEvent for round 3", e)
	}
}

// fabricatedVote is what a Byzantine sender can put on the wire unaided: an
// arbitrary VoteInfo, its hash bound into a LedgerCommitInfo, and its own valid
// signature over that pair. Nothing in the message ties the round it claims to
// anything else.
func fabricatedVote(from ID, round Round) *VoteMsg {
	voteInfo := VoteInfo{ID: Hash{byte(round), byte(round >> 8)}, Round: round}
	commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}
	return &VoteMsg{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		Sender:           from,
		Sig:              signAs(from, LedgerCommitDigest(commit)),
	}
}

// TestCoreBoundsVoteAccumulation is the accumulator bound. BlockTree.votes is
// keyed on the LedgerCommitInfo digest and a sender picks that freely, so every
// fabricated vote opens a bucket of its own. Pruning is no answer: it only runs
// on a commit, and these votes can never reach a quorum to produce one.
func TestCoreBoundsVoteAccumulation(t *testing.T) {
	f := newCoreFixture(t)
	v := newTestVerifier()

	const votes = 10000
	for r := Round(1); r <= votes; r++ {
		m := fabricatedVote(1, r)
		if !v.VerifyVote(m) {
			t.Fatalf("setup: the fabricated vote for round %d must pass the edge", r)
		}
		f.core.Step(VoteEvent{Msg: m})
	}
	if got := f.core.State().Round; got != 1 {
		t.Fatalf("round moved to %d on votes that can never form a quorum", got)
	}
	if got, want := len(f.core.tree.votes), maxRoundLead+1; got > want {
		t.Errorf("%d vote buckets after %d fabricated rounds, want at most %d", got, votes, want)
	}
}

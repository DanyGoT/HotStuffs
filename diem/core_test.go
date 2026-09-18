package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/consensus"
	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// The tests here cover the boundary the paper delegates to "other parts of the
// system": everything Core drops before a message is allowed to touch state.
// A Byzantine replica's whole surface is what it can put on the wire, so a
// message that fails any of these checks must leave no trace.

// coreFixture is replica 2 in a group of 4, started and sitting in round 1.
// Replica 1 leads round 1, so this replica is a voter; it leads rounds 2 and 3,
// so it is also the collector for round 1's votes.
type coreFixture struct {
	core *Core
	net  *recordNet
	sink *recordSink
}

func newCoreFixture(t *testing.T) *coreFixture {
	t.Helper()
	f := &coreFixture{net: &recordNet{}, sink: &recordSink{}}
	ids := []ID{1, 2, 3, 4}
	f.core = New(Config{
		ID:         2,
		Validators: ids,
		Ledger:     NewMemLedger(),
		MemPool:    NewFIFOPool(16, 2),
		Crypto:     nocrypto.New(2, testN),
		Transport:  f.net,
		Clock:      fake.NewClock(time.Unix(0, 0)),
		Duration:   consensus.NewViewDuration(100*time.Millisecond, time.Second, 2),
		Sink:       f.sink,
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
		{"signature is by someone other than the sender", func() *ProposalMsg {
			p := proposal(1, 1, 1)
			p.Sig = signAs(3, p.Block.ID())
			return p
		}},
		{"signature covers something other than the block", func() *ProposalMsg {
			p := proposal(1, 1, 1)
			p.Sig = signAs(1, Hash{0xff})
			return p
		}},
		{"round is not the round this replica is in", func() *ProposalMsg {
			return proposal(1, 1, 7)
		}},
		{"carries a TC its own QC already makes redundant", func() *ProposalMsg {
			// Well-formedness: a proposal for round r carries the TC of r-1
			// only when its QC is not from r-1. Genesis is from round 0, so
			// any TC here is redundant and the proposal is ill-formed.
			p := proposal(1, 1, 1)
			p.LastRoundTC = &TC{Round: 0}
			return p
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

// TestCoreRejectsForgedCertificate pins the check on the certificates a
// message carries, rather than on the message envelope. An unsigned QC that
// claims a high round is the cheapest attack there is: accepting it would drag
// the replica's round and its highest certificate forward on no evidence, and
// no later leader or round check would notice.
func TestCoreRejectsForgedCertificate(t *testing.T) {
	forged := &QC{VoteInfo: VoteInfo{ID: Hash{0x99}, Round: 40}}

	t.Run("on a proposal", func(t *testing.T) {
		f := newCoreFixture(t)
		p := proposal(1, 1, 1)
		p.HighCommitQC = forged
		f.core.Step(ProposalEvent{Msg: p})
		assertUnmoved(t, f)
	})
	t.Run("as a block's parent certificate", func(t *testing.T) {
		f := newCoreFixture(t)
		b := NewBlock(1, 41, [][]byte{{0xaa}}, forged)
		f.core.Step(ProposalEvent{Msg: &ProposalMsg{
			Block: b, HighCommitQC: genesisQC, Sender: 1, Sig: signAs(1, b.ID()),
		}})
		assertUnmoved(t, f)
	})
	t.Run("on a timeout", func(t *testing.T) {
		f := newCoreFixture(t)
		m := timeoutFrom(t, 1)
		m.HighCommitQC = forged
		f.core.Step(TimeoutEvent{Msg: m})
		assertUnmoved(t, f)
	})
	t.Run("on a vote", func(t *testing.T) {
		f := newCoreFixture(t)
		p := proposal(1, 1, 1)
		f.core.Step(ProposalEvent{Msg: p})
		v := voteFor(t, 1, p.Block)
		v.HighCommitQC = forged
		f.core.Step(VoteEvent{Msg: v})
		assertUnmoved(t, f)
	})
}

// assertUnmoved checks the replica is still where newCoreFixture left it.
func assertUnmoved(t *testing.T, f *coreFixture) {
	t.Helper()
	s := f.core.State()
	if s.Round != 1 {
		t.Errorf("round moved to %d on a forged certificate", s.Round)
	}
	if s.HighQCRound != 0 {
		t.Errorf("high QC moved to round %d on a forged certificate", s.HighQCRound)
	}
	if s.HighCommitRound != 0 {
		t.Errorf("high commit QC moved to round %d on a forged certificate", s.HighCommitRound)
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
	v := NewSafety(from, testQuorum, signer, ledger, tree).MakeVote(b, nil)
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

func TestCoreRejectsVotes(t *testing.T) {
	tamper := map[string]func(*VoteMsg){
		"VoteInfo does not match the hash the signature binds": func(v *VoteMsg) {
			v.VoteInfo.Round = 9
		},
		"signature is by someone other than the sender": func(v *VoteMsg) {
			v.Sender = 4
		},
		"signature covers something other than the ledger commit info": func(v *VoteMsg) {
			v.Sig = signAs(v.Sender, Hash{0xff})
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			f := newCoreFixture(t)
			p := proposal(1, 1, 1)
			f.core.Step(ProposalEvent{Msg: p})

			for _, from := range []ID{1, 3, 4} {
				v := voteFor(t, from, p.Block)
				break_(v)
				f.core.Step(VoteEvent{Msg: v})
			}
			if got := f.core.State().Round; got != 1 {
				t.Errorf("advanced to round %d on votes that should have been dropped", got)
			}
			if len(f.net.proposals) != 0 {
				t.Error("proposed on a certificate built from tampered votes")
			}
		})
	}
}

// timeoutFrom builds replica from's honest timeout for round 1 over genesis.
func timeoutFrom(t *testing.T, from ID) *TimeoutMsg {
	t.Helper()
	ledger := NewMemLedger()
	signer := nocrypto.New(from, testN)
	tree := NewBlockTree(from, testQuorum, ledger, signer)
	info := NewSafety(from, testQuorum, signer, ledger, tree).MakeTimeout(1, genesisQC, nil)
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

func TestCoreRejectsTimeouts(t *testing.T) {
	tamper := map[string]func(*TimeoutMsg){
		"signature is by someone other than the sender": func(m *TimeoutMsg) {
			m.TmoInfo.Sender = 4
		},
		"signature covers a different round": func(m *TimeoutMsg) {
			m.TmoInfo.Sig = signAs(m.TmoInfo.Sender, TimeoutDigest(9, 0))
		},
		"high QC is forged": func(m *TimeoutMsg) {
			m.TmoInfo.HighQC = &QC{VoteInfo: VoteInfo{ID: Hash{0x99}, Round: 5}}
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			f := newCoreFixture(t)
			for _, from := range []ID{1, 3} {
				m := timeoutFrom(t, from)
				break_(m)
				f.core.Step(TimeoutEvent{Msg: m})
			}
			if len(f.net.timeouts) != 0 {
				t.Error("amplified timeouts that should have been dropped")
			}
		})
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
	sink := &recordSink{}
	core := New(Config{
		ID:         1,
		Validators: []ID{1, 2, 3, 4},
		Ledger:     NewMemLedger(),
		MemPool:    NewFIFOPool(16, 2),
		Crypto:     nocrypto.New(1, testN),
		Transport:  &recordNet{},
		Clock:      clock,
		Duration:   consensus.NewViewDuration(100*time.Millisecond, time.Second, 2),
		Sink:       sink,
	})
	core.Start()
	core.Stop()
	clock.Advance(time.Second)
	if len(sink.events) != 0 {
		t.Fatalf("a stopped core pushed %d timer events", len(sink.events))
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

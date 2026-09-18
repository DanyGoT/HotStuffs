package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/consensus"
	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// newTestLeaderElection returns a LeaderElection for validators, wired to its
// own ledger and pacemaker (replica id 1) so the pacemaker's round can be
// driven independently in each test.
func newTestLeaderElection(t *testing.T, validators []ID, window, exclude int) (*LeaderElection, *Pacemaker, *MemLedger) {
	t.Helper()
	n := len(validators)
	quorum := hotstuff.QuorumSize(n)
	faulty := hotstuff.Faulty(n)
	ledger := NewMemLedger()
	crypto := nocrypto.New(1, n)
	tree := NewBlockTree(1, quorum, ledger, crypto)
	safety := NewSafety(1, quorum, crypto, ledger, tree)
	dur := consensus.NewViewDuration(10*time.Millisecond, time.Second, 2)
	pm := NewPacemaker(quorum, faulty, fake.NewClock(time.Unix(0, 0)), dur, &recordSink{}, &recordNet{}, safety, tree)
	le := NewLeaderElection(validators, window, exclude, ledger, pm)
	return le, pm, ledger
}

func TestGetLeaderRoundRobinTwoRoundsEachRegardlessOfOrder(t *testing.T) {
	orderA := []ID{1, 2, 3, 4}
	orderB := []ID{4, 3, 2, 1}
	leA, _, _ := newTestLeaderElection(t, orderA, 3, 1)
	leB, _, _ := newTestLeaderElection(t, orderB, 3, 1)

	want := []ID{1, 1, 2, 2, 3, 3, 4, 4, 1, 1}
	for r, id := range want {
		if got := leA.GetLeader(Round(r)); got != id {
			t.Errorf("orderA: GetLeader(%d) = %d, want %d", r, got, id)
		}
		if got := leB.GetLeader(Round(r)); got != id {
			t.Errorf("orderB: GetLeader(%d) = %d, want %d", r, got, id)
		}
	}
}

func TestGetLeaderPrefersReputationLeader(t *testing.T) {
	le, _, _ := newTestLeaderElection(t, []ID{1, 2, 3, 4}, 3, 1)
	le.reputationLeaders[10] = 99

	if got := le.GetLeader(10); got != 99 {
		t.Fatalf("GetLeader(10) = %d, want the reputation-elected 99", got)
	}
	// A round with no reputation entry still falls back to round-robin.
	if got, want := le.GetLeader(11), le.validators[(uint64(11)/2)%uint64(len(le.validators))]; got != want {
		t.Fatalf("GetLeader(11) = %d, want round-robin fallback %d", got, want)
	}
}

func TestUpdateLeadersRequiresBothConditions(t *testing.T) {
	tests := []struct {
		name        string
		parentRound Round
		round       Round
		gotoRound   Round // pacemaker current round to reach before UpdateLeaders
	}{
		{"contiguous 2-chain but round mismatch", 1, 2, 5},
		{"round matches but not a contiguous 2-chain", 0, 2, 3},
		{"neither holds", 0, 2, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			le, pm, _ := newTestLeaderElection(t, []ID{1, 2, 3, 4}, 1, 1)
			if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: tt.gotoRound - 1}}) {
				t.Fatalf("setup: could not advance pacemaker to round %d", tt.gotoRound)
			}
			if pm.CurrentRound() != tt.gotoRound {
				t.Fatalf("setup: pacemaker at round %d, want %d", pm.CurrentRound(), tt.gotoRound)
			}

			qc := &QC{VoteInfo: VoteInfo{Round: tt.round, ParentRound: tt.parentRound}}
			le.UpdateLeaders(qc)

			if len(le.reputationLeaders) != 0 {
				t.Fatalf("UpdateLeaders elected a leader despite failing the round condition: %v", le.reputationLeaders)
			}
		})
	}
}

func TestElectReputationLeaderExcludesRecentAuthorsAndPicksFromWindow(t *testing.T) {
	ledger := NewMemLedger()
	// b1 extends genesis; its author (5) must be excluded from the pick even
	// though 5 also appears among the window's signers.
	b1 := NewBlock(5, 1, nil, &QC{VoteInfo: VoteInfo{ID: GenesisBlock().ID()}})
	ledger.Speculate(b1)
	ledger.Commit(b1.ID())

	le := &LeaderElection{ledger: ledger, windowSize: 1, excludeSize: 1}
	qc := &QC{
		VoteInfo:   VoteInfo{Round: 42, ParentID: b1.ID()},
		Signatures: []Signature{{Signer: 5}, {Signer: 101}},
	}

	id, ok := le.electReputationLeader(qc)
	if !ok {
		t.Fatal("electReputationLeader reported no candidate")
	}
	if id != 101 {
		t.Fatalf("elected %d, want 101 (5 is the excluded author of the last committed block)", id)
	}
}

func TestElectReputationLeaderFallsBackWhenHistoryTooShort(t *testing.T) {
	ledger := NewMemLedger() // only genesis is committed
	le := &LeaderElection{ledger: ledger, windowSize: 5, excludeSize: 1}
	qc := &QC{VoteInfo: VoteInfo{Round: 1, ParentID: GenesisBlock().ID()}}

	if _, ok := le.electReputationLeader(qc); ok {
		t.Fatal("electReputationLeader found a candidate from a history shorter than the window, want a fallback")
	}
}

func TestPickIsDeterministicAndInRange(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 32} {
		for _, seed := range []Round{0, 1, 42, 1_000_000} {
			a := pick(seed, n)
			b := pick(seed, n)
			if a != b {
				t.Fatalf("pick(%d, %d) not deterministic: %d then %d", seed, n, a, b)
			}
			if a < 0 || a >= n {
				t.Fatalf("pick(%d, %d) = %d, out of range [0, %d)", seed, n, a, n)
			}
		}
	}
}

// TestUpdateLeadersAgreesAcrossReplicas checks the paper's requirement that
// every replica seeing the same qc at the same round elects the same leader,
// independent of the order its own validators slice was constructed with.
func TestUpdateLeadersAgreesAcrossReplicas(t *testing.T) {
	ledger := NewMemLedger()
	b1 := NewBlock(5, 1, nil, &QC{VoteInfo: VoteInfo{ID: GenesisBlock().ID()}})
	ledger.Speculate(b1)
	ledger.Commit(b1.ID())

	qc := &QC{
		VoteInfo:   VoteInfo{Round: 2, ParentRound: 1, ParentID: b1.ID()},
		Signatures: []Signature{{Signer: 5}, {Signer: 101}},
	}

	le1, pm1, _ := newTestLeaderElection(t, []ID{1, 2, 3, 4}, 1, 1)
	le2, pm2, _ := newTestLeaderElection(t, []ID{4, 3, 2, 1}, 1, 1)
	le1.ledger = ledger
	le2.ledger = ledger // both replicas observed the same committed chain

	for _, pm := range []*Pacemaker{pm1, pm2} {
		if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 2}}) {
			t.Fatal("setup: could not advance pacemaker to round 3")
		}
	}

	le1.UpdateLeaders(qc)
	le2.UpdateLeaders(qc)

	got1, ok1 := le1.reputationLeaders[4]
	got2, ok2 := le2.reputationLeaders[4]
	if !ok1 || !ok2 {
		t.Fatalf("expected both replicas to elect a leader for round 4: ok1=%v ok2=%v", ok1, ok2)
	}
	if got1 != got2 {
		t.Fatalf("replicas disagree on the round-4 leader: %d vs %d", got1, got2)
	}
	if got1 != 101 {
		t.Fatalf("elected %d, want 101", got1)
	}
	if leader := le1.GetLeader(4); leader != got1 {
		t.Fatalf("GetLeader(4) = %d, want the elected reputation leader %d", leader, got1)
	}
}

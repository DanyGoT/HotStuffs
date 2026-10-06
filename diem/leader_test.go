package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// newTestLeaderElection returns a LeaderElection for validators, wired to its
// own ledger and pacemaker (replica id 1) so the pacemaker's round can be
// driven independently in each test.
func newTestLeaderElection(t *testing.T, validators []uint32, window, exclude int) (*LeaderElection, *Pacemaker, *MemLedger) {
	t.Helper()
	n := len(validators)
	quorum := QuorumSize(n)
	faulty := Faulty(n)
	ledger := NewMemLedger()
	crypto := newTestSigner(n)
	tree := NewBlockTree(1, quorum, ledger, crypto)
	safety := NewSafety(1, NewVerifier(crypto, quorum), crypto, ledger, tree)
	dur := NewBackoff(10*time.Millisecond, time.Second, 2)
	pm := NewPacemaker(quorum, faulty, newFakeClock(), dur, func(Event) {}, &recordNet{}, safety, tree)
	le := NewLeaderElection(validators, window, exclude, ledger, pm)
	return le, pm, ledger
}

func TestGetLeaderRoundRobinTwoRoundsEachRegardlessOfOrder(t *testing.T) {
	orderA := []uint32{1, 2, 3, 4}
	orderB := []uint32{4, 3, 2, 1}
	leA, _, _ := newTestLeaderElection(t, orderA, 3, 1)
	leB, _, _ := newTestLeaderElection(t, orderB, 3, 1)

	want := []uint32{1, 1, 2, 2, 3, 3, 4, 4, 1, 1}
	for r, id := range want {
		if got := leA.GetLeader(uint64(r)); got != id {
			t.Errorf("orderA: GetLeader(%d) = %d, want %d", r, got, id)
		}
		if got := leB.GetLeader(uint64(r)); got != id {
			t.Errorf("orderB: GetLeader(%d) = %d, want %d", r, got, id)
		}
	}
}

func TestGetLeaderPrefersReputationLeader(t *testing.T) {
	le, _, _ := newTestLeaderElection(t, []uint32{1, 2, 3, 4}, 3, 1)
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
		parentRound uint64
		round       uint64
		gotoRound   uint64 // pacemaker current round to reach before UpdateLeaders
	}{
		{"contiguous 2-chain but round mismatch", 1, 2, 5},
		{"round matches but not a contiguous 2-chain", 0, 2, 3},
		{"neither holds", 0, 2, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			le, pm, _ := newTestLeaderElection(t, []uint32{1, 2, 3, 4}, 1, 1)
			if !pm.AdvanceRoundQC(bareQC(nil, tt.gotoRound-1)) {
				t.Fatalf("setup: could not advance pacemaker to round %d", tt.gotoRound)
			}
			if pm.CurrentRound() != tt.gotoRound {
				t.Fatalf("setup: pacemaker at round %d, want %d", pm.CurrentRound(), tt.gotoRound)
			}

			qc := qcWith(voteInfo(nil, tt.round, nil, tt.parentRound), nil)
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
	b1 := NewBlock(5, 1, nil, bareQC(GenesisBlock().GetId(), 0))
	ledger.Speculate(b1)
	ledger.Commit(b1.GetId())

	le := &LeaderElection{ledger: ledger, windowSize: 1, excludeSize: 1}
	qc := diempb.QuorumCert_builder{
		VoteInfo:   voteInfo(nil, 42, b1.GetId(), 0),
		Signatures: sigs(5, 101),
	}.Build()

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
	qc := qcWith(voteInfo(nil, 1, GenesisBlock().GetId(), 0), nil)

	if _, ok := le.electReputationLeader(qc); ok {
		t.Fatal("electReputationLeader found a candidate from a history shorter than the window, want a fallback")
	}
}

func TestPickIsDeterministicAndInRange(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 32} {
		for _, seed := range []uint64{0, 1, 42, 1_000_000} {
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
	b1 := NewBlock(5, 1, nil, bareQC(GenesisBlock().GetId(), 0))
	ledger.Speculate(b1)
	ledger.Commit(b1.GetId())

	qc := diempb.QuorumCert_builder{
		VoteInfo:   voteInfo(nil, 2, b1.GetId(), 1),
		Signatures: sigs(5, 101),
	}.Build()

	le1, pm1, _ := newTestLeaderElection(t, []uint32{1, 2, 3, 4}, 1, 1)
	le2, pm2, _ := newTestLeaderElection(t, []uint32{4, 3, 2, 1}, 1, 1)
	le1.ledger = ledger
	le2.ledger = ledger // both replicas observed the same committed chain

	for _, pm := range []*Pacemaker{pm1, pm2} {
		if !pm.AdvanceRoundQC(bareQC(nil, 2)) {
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

package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// recordNet is a Transport double that records what was sent, distinct from
// sim_test.go's simNet, which delivers into a running sim instead.
type recordNet struct {
	proposals []*ProposalMsg
	votes     []*VoteMsg
	voteTo    []ID
	timeouts  []*TimeoutMsg
}

func (n *recordNet) Proposal(p *ProposalMsg) { n.proposals = append(n.proposals, p) }
func (n *recordNet) Vote(v *VoteMsg, to ID) {
	n.votes = append(n.votes, v)
	n.voteTo = append(n.voteTo, to)
}
func (n *recordNet) Timeout(m *TimeoutMsg) { n.timeouts = append(n.timeouts, m) }

var _ Transport = (*recordNet)(nil)

// recordSink returns a sink appending the events pushed to it, in order, to
// *log.
func recordSink(log *[]Event) func(Event) {
	return func(e Event) { *log = append(*log, e) }
}

// newTestPacemaker returns a pacemaker for a replica set of size n, replica id
// 1, wired to test doubles for the clock, sink and transport.
func newTestPacemaker(t *testing.T, n int) (*Pacemaker, *fake.Clock, *recordNet, *[]Event) {
	t.Helper()
	quorum := hotstuff.QuorumSize(n)
	faulty := hotstuff.Faulty(n)
	clock := fake.NewClock(time.Unix(0, 0))
	net := &recordNet{}
	events := new([]Event)
	ledger := NewMemLedger()
	crypto := nocrypto.New(1, n)
	tree := NewBlockTree(1, quorum, ledger, crypto)
	safety := NewSafety(1, NewVerifier(crypto, quorum), crypto, ledger, tree)
	dur := hotstuff.NewDuration(10*time.Millisecond, time.Second, 2)
	pm := NewPacemaker(quorum, faulty, clock, dur, recordSink(events), net, safety, tree)
	return pm, clock, net, events
}

// timeoutInfoFrom builds a well-signed TimeoutInfo for sender, as if it were
// replica sender's own Safety.MakeTimeout output.
func timeoutInfoFrom(t *testing.T, sender ID, n int, round, highQCRound Round) TimeoutInfo {
	t.Helper()
	sig, err := nocrypto.New(sender, n).Sign(TimeoutDigest(round, highQCRound))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return TimeoutInfo{
		Round:  round,
		HighQC: &QC{VoteInfo: VoteInfo{Round: highQCRound}},
		Sender: sender,
		Sig:    sig,
	}
}

func TestAdvanceRoundQCBelowCurrentRoundChangesNothing(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 4}}) {
		t.Fatal("setup: AdvanceRoundQC(round 4) should have entered round 5")
	}
	pm.lastRoundTC = &TC{Round: 4} // seed a TC to prove it survives untouched

	moved := pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 3}})
	if moved {
		t.Fatal("AdvanceRoundQC returned true for a QC below the current round")
	}
	if pm.CurrentRound() != 5 {
		t.Fatalf("CurrentRound() = %d, want 5 (unchanged)", pm.CurrentRound())
	}
	if pm.LastRoundTC() == nil {
		t.Fatal("LastRoundTC was cleared despite AdvanceRoundQC returning false")
	}
}

func TestAdvanceRoundQCAtOrAboveEntersNextRoundAndClearsTC(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	if !pm.AdvanceRoundTC(&TC{Round: 2}) {
		t.Fatal("setup: AdvanceRoundTC(round 2) should have entered round 3")
	}
	if pm.LastRoundTC() == nil {
		t.Fatal("setup: LastRoundTC not recorded")
	}

	// A QC at exactly the current round is "at or above".
	moved := pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 3}})
	if !moved {
		t.Fatal("AdvanceRoundQC returned false for a QC at the current round")
	}
	if pm.CurrentRound() != 4 {
		t.Fatalf("CurrentRound() = %d, want 4", pm.CurrentRound())
	}
	if pm.LastRoundTC() != nil {
		t.Fatal("LastRoundTC was not cleared by AdvanceRoundQC")
	}
}

func TestAdvanceRoundTCNilReturnsFalse(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	if pm.AdvanceRoundTC(nil) {
		t.Fatal("AdvanceRoundTC(nil) returned true")
	}
	if pm.CurrentRound() != 0 {
		t.Fatalf("CurrentRound() = %d, want 0 (unchanged)", pm.CurrentRound())
	}
}

func TestAdvanceRoundTCBelowCurrentRoundReturnsFalse(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 4}}) {
		t.Fatal("setup: AdvanceRoundQC(round 4) should have entered round 5")
	}
	if pm.AdvanceRoundTC(&TC{Round: 3}) {
		t.Fatal("AdvanceRoundTC returned true for a TC below the current round")
	}
	if pm.CurrentRound() != 5 {
		t.Fatalf("CurrentRound() = %d, want 5 (unchanged)", pm.CurrentRound())
	}
}

func TestAdvanceRoundTCEntersNextRoundAndRecordsTC(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	tc := &TC{Round: 2}
	if !pm.AdvanceRoundTC(tc) {
		t.Fatal("AdvanceRoundTC(round 2) returned false")
	}
	if pm.CurrentRound() != 3 {
		t.Fatalf("CurrentRound() = %d, want 3", pm.CurrentRound())
	}
	if pm.LastRoundTC() != tc {
		t.Fatal("LastRoundTC was not recorded")
	}
}

func TestStartTimerPushesLocalTimeoutEventForItsOwnRound(t *testing.T) {
	pm, clock, _, events := newTestPacemaker(t, 4)
	pm.startTimer(7)

	clock.Advance(pm.dur.Duration())

	if len(*events) != 1 {
		t.Fatalf("sink got %d events, want 1", len(*events))
	}
	ev, ok := (*events)[0].(LocalTimeoutEvent)
	if !ok {
		t.Fatalf("event type = %T, want LocalTimeoutEvent", (*events)[0])
	}
	if ev.Round != 7 {
		t.Fatalf("LocalTimeoutEvent.Round = %d, want 7", ev.Round)
	}
}

func TestProcessRemoteTimeoutPastRoundReturnsNil(t *testing.T) {
	pm, _, net, _ := newTestPacemaker(t, 4)
	if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 5}}) {
		t.Fatal("setup: AdvanceRoundQC(round 5) should have entered round 6")
	}

	tc := pm.ProcessRemoteTimeout(&TimeoutMsg{TmoInfo: timeoutInfoFrom(t, 2, 4, 5, 5)})
	if tc != nil {
		t.Fatal("a timeout for a past round produced a TC")
	}
	if len(net.timeouts) != 0 {
		t.Fatalf("a timeout for a past round triggered %d self-timeouts, want 0", len(net.timeouts))
	}
}

func TestProcessRemoteTimeoutDuplicateSenderCountsOnce(t *testing.T) {
	pm, _, net, _ := newTestPacemaker(t, 4) // n=4: f=1, quorum=3, so f+1=2 distinct senders self-times-out
	if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 0}}) {
		t.Fatal("setup: AdvanceRoundQC(round 0) should have entered round 1")
	}

	info := timeoutInfoFrom(t, 2, 4, 1, 5)
	pm.ProcessRemoteTimeout(&TimeoutMsg{TmoInfo: info})
	pm.ProcessRemoteTimeout(&TimeoutMsg{TmoInfo: info}) // same sender again

	if len(net.timeouts) != 0 {
		t.Fatalf("a duplicate sender was counted twice: got %d self-timeouts, want 0 (only 1 distinct sender)", len(net.timeouts))
	}
}

func TestProcessRemoteTimeoutBrachaAmplificationAtFPlus1(t *testing.T) {
	pm, _, net, _ := newTestPacemaker(t, 4) // f=1, so f+1=2 distinct senders
	if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 0}}) {
		t.Fatal("setup: AdvanceRoundQC(round 0) should have entered round 1")
	}

	pm.ProcessRemoteTimeout(&TimeoutMsg{TmoInfo: timeoutInfoFrom(t, 2, 4, 1, 5)})
	if len(net.timeouts) != 0 {
		t.Fatalf("self-timeout fired at 1 distinct sender, want it to wait for f+1=2")
	}

	pm.ProcessRemoteTimeout(&TimeoutMsg{TmoInfo: timeoutInfoFrom(t, 3, 4, 1, 7)})
	if len(net.timeouts) != 1 {
		t.Fatalf("got %d self-timeouts at f+1=2 distinct senders, want exactly 1", len(net.timeouts))
	}
	own := net.timeouts[0]
	if own.TmoInfo.Sender != 1 {
		t.Fatalf("self-timeout sender = %d, want this replica's id (1)", own.TmoInfo.Sender)
	}
	if own.TmoInfo.Round != 1 {
		t.Fatalf("self-timeout round = %d, want 1", own.TmoInfo.Round)
	}
}

func TestProcessRemoteTimeoutQuorumFormsValidTC(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4) // quorum=3
	if !pm.AdvanceRoundQC(&QC{VoteInfo: VoteInfo{Round: 0}}) {
		t.Fatal("setup: AdvanceRoundQC(round 0) should have entered round 1")
	}

	// Descending sender ids: a certificate's canonical signer order is a
	// property of the certificate, not of the order its parts arrived in.
	senders := []struct {
		id          ID
		highQCRound Round
	}{
		{4, 9},
		{3, 7},
		{2, 5},
	}
	var tc *TC
	for _, s := range senders {
		tc = pm.ProcessRemoteTimeout(&TimeoutMsg{TmoInfo: timeoutInfoFrom(t, s.id, 4, 1, s.highQCRound)})
	}
	if tc == nil {
		t.Fatal("no TC formed at quorum (3 distinct senders)")
	}
	if tc.Round != 1 {
		t.Fatalf("tc.Round = %d, want 1", tc.Round)
	}
	if len(tc.Votes) != 3 {
		t.Fatalf("tc has %d votes, want 3 (quorum)", len(tc.Votes))
	}

	want := map[ID]Round{2: 5, 3: 7, 4: 9}
	for _, v := range tc.Votes {
		got, ok := want[v.Sig.Signer]
		if !ok {
			t.Fatalf("vote signed by unexpected sender %d", v.Sig.Signer)
		}
		if got != v.HighQCRound {
			t.Fatalf("vote for sender %d pairs HighQCRound %d, want %d (each sender's own high_qc round)",
				v.Sig.Signer, v.HighQCRound, got)
		}
	}

	if !NewVerifier(nocrypto.New(1, 4), 3).VerifyTC(tc) {
		t.Fatal("the TC produced by ProcessRemoteTimeout does not verify at the edge")
	}
}

// TestLocalTimeoutRoundDropsRedundantTC pins a gap between two parts of the
// paper. local_timeout_round (3.5) broadcasts last_round_tc unconditionally,
// but the well-formedness rule says a round-r message carries the TC of r-1
// exactly when its certificate is not from r-1 — so a replica holding both a
// TC for r-1 and a QC for r-1 broadcasts a timeout every honest replica
// discards, and its contribution to the round's TC is silently lost.
//
// The state is reachable and provoked here deterministically: enter round 3 on
// a TC for round 2, then take a late QC for round 2. advance_round_qc returns
// false without clearing last_round_tc, which is the paper's own text, while
// BlockTree.process_qc has already raised high_qc.
func TestLocalTimeoutRoundDropsRedundantTC(t *testing.T) {
	pm, _, net, _ := newTestPacemaker(t, testN)

	if !pm.AdvanceRoundTC(makeTC(2, 1, 1, 1)) {
		t.Fatal("AdvanceRoundTC(TC for round 2) = false, want the replica to enter round 3")
	}
	qc := makeQC(VoteInfo{ID: Hash{1}, Round: 2, ParentRound: 1}, Hash{}, 1, 2, 3)
	pm.tree.ProcessQC(qc)
	if pm.AdvanceRoundQC(qc) {
		t.Fatal("AdvanceRoundQC(QC for round 2) = true, want a certificate below the current round to change nothing")
	}

	pm.LocalTimeoutRound()

	if len(net.timeouts) != 1 {
		t.Fatalf("broadcast %d timeouts, want 1", len(net.timeouts))
	}
	if m := net.timeouts[0]; !m.WellFormed() {
		t.Fatalf("broadcast an ill-formed timeout: round %d over a high_qc for round %d, carrying a TC for round %d; every honest replica discards it",
			m.TmoInfo.Round, m.TmoInfo.HighQC.Round(), m.LastRoundTC.Round)
	}
}

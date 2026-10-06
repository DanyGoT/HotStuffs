package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// recordNet is a Transport double that records what was sent, distinct from
// sim_test.go's simNet, which delivers into a running sim instead.
type recordNet struct {
	proposals []*diempb.ProposalMsg
	votes     []*diempb.VoteMsg
	voteTo    []uint32
	timeouts  []*diempb.TimeoutMsg
}

func (n *recordNet) Proposal(p *diempb.ProposalMsg) { n.proposals = append(n.proposals, p) }
func (n *recordNet) Vote(v *diempb.VoteMsg, to uint32) {
	n.votes = append(n.votes, v)
	n.voteTo = append(n.voteTo, to)
}
func (n *recordNet) Timeout(m *diempb.TimeoutMsg) { n.timeouts = append(n.timeouts, m) }

var _ Transport = (*recordNet)(nil)

// recordSink returns a sink appending the events pushed to it, in order, to
// *log.
func recordSink(log *[]Event) func(Event) {
	return func(e Event) { *log = append(*log, e) }
}

// newTestPacemaker returns a pacemaker for a replica set of size n, replica id
// 1, wired to test doubles for the clock, sink and transport.
func newTestPacemaker(t *testing.T, n int) (*Pacemaker, *fakeClock, *recordNet, *[]Event) {
	t.Helper()
	quorum := QuorumSize(n)
	faulty := Faulty(n)
	clock := newFakeClock()
	net := &recordNet{}
	events := new([]Event)
	ledger := NewMemLedger()
	crypto := newTestSigner(n)
	tree := NewBlockTree(1, quorum, ledger, crypto)
	safety := NewSafety(1, NewVerifier(crypto, quorum), crypto, ledger, tree)
	dur := NewBackoff(10*time.Millisecond, time.Second, 2)
	pm := NewPacemaker(quorum, faulty, clock, dur, recordSink(events), net, safety, tree)
	return pm, clock, net, events
}

// timeoutInfoFrom builds a well-signed TimeoutInfo for sender, as if it were
// replica sender's own Safety.MakeTimeout output.
func timeoutInfoFrom(t *testing.T, sender uint32, n int, round, highQCRound uint64) *diempb.TimeoutInfo {
	t.Helper()
	sig, err := newTestSigner(n).Sign(TimeoutDigest(round, highQCRound))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return diempb.TimeoutInfo_builder{
		Round:  round,
		HighQc: bareQC(nil, highQCRound),
		Sender: sender,
		Sig:    diempb.Signature_builder{Signer: sender, Sig: sig}.Build(),
	}.Build()
}

func timeoutMsg(info *diempb.TimeoutInfo) *diempb.TimeoutMsg {
	return diempb.TimeoutMsg_builder{TmoInfo: info}.Build()
}

func TestAdvanceRoundQCBelowCurrentRoundChangesNothing(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	if !pm.AdvanceRoundQC(bareQC(nil, 4)) {
		t.Fatal("setup: AdvanceRoundQC(round 4) should have entered round 5")
	}
	pm.lastRoundTC = makeTC(4) // seed a TC to prove it survives untouched

	moved := pm.AdvanceRoundQC(bareQC(nil, 3))
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
	if !pm.AdvanceRoundTC(makeTC(2)) {
		t.Fatal("setup: AdvanceRoundTC(round 2) should have entered round 3")
	}
	if pm.LastRoundTC() == nil {
		t.Fatal("setup: LastRoundTC not recorded")
	}

	// A QC at exactly the current round is "at or above".
	moved := pm.AdvanceRoundQC(bareQC(nil, 3))
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
	if !pm.AdvanceRoundQC(bareQC(nil, 4)) {
		t.Fatal("setup: AdvanceRoundQC(round 4) should have entered round 5")
	}
	if pm.AdvanceRoundTC(makeTC(3)) {
		t.Fatal("AdvanceRoundTC returned true for a TC below the current round")
	}
	if pm.CurrentRound() != 5 {
		t.Fatalf("CurrentRound() = %d, want 5 (unchanged)", pm.CurrentRound())
	}
}

func TestAdvanceRoundTCEntersNextRoundAndRecordsTC(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4)
	tc := makeTC(2)
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
	if !pm.AdvanceRoundQC(bareQC(nil, 5)) {
		t.Fatal("setup: AdvanceRoundQC(round 5) should have entered round 6")
	}

	tc := pm.ProcessRemoteTimeout(timeoutMsg(timeoutInfoFrom(t, 2, 4, 5, 5)))
	if tc != nil {
		t.Fatal("a timeout for a past round produced a TC")
	}
	if len(net.timeouts) != 0 {
		t.Fatalf("a timeout for a past round triggered %d self-timeouts, want 0", len(net.timeouts))
	}
}

func TestProcessRemoteTimeoutDuplicateSenderCountsOnce(t *testing.T) {
	pm, _, net, _ := newTestPacemaker(t, 4) // n=4: f=1, quorum=3, so f+1=2 distinct senders self-times-out
	if !pm.AdvanceRoundQC(bareQC(nil, 0)) {
		t.Fatal("setup: AdvanceRoundQC(round 0) should have entered round 1")
	}

	info := timeoutInfoFrom(t, 2, 4, 1, 5)
	pm.ProcessRemoteTimeout(timeoutMsg(info))
	pm.ProcessRemoteTimeout(timeoutMsg(info)) // same sender again

	if len(net.timeouts) != 0 {
		t.Fatalf("a duplicate sender was counted twice: got %d self-timeouts, want 0 (only 1 distinct sender)", len(net.timeouts))
	}
}

func TestProcessRemoteTimeoutBrachaAmplificationAtFPlus1(t *testing.T) {
	pm, _, net, _ := newTestPacemaker(t, 4) // f=1, so f+1=2 distinct senders
	if !pm.AdvanceRoundQC(bareQC(nil, 0)) {
		t.Fatal("setup: AdvanceRoundQC(round 0) should have entered round 1")
	}

	pm.ProcessRemoteTimeout(timeoutMsg(timeoutInfoFrom(t, 2, 4, 1, 5)))
	if len(net.timeouts) != 0 {
		t.Fatalf("self-timeout fired at 1 distinct sender, want it to wait for f+1=2")
	}

	pm.ProcessRemoteTimeout(timeoutMsg(timeoutInfoFrom(t, 3, 4, 1, 7)))
	if len(net.timeouts) != 1 {
		t.Fatalf("got %d self-timeouts at f+1=2 distinct senders, want exactly 1", len(net.timeouts))
	}
	own := net.timeouts[0]
	if own.GetTmoInfo().GetSender() != 1 {
		t.Fatalf("self-timeout sender = %d, want this replica's id (1)", own.GetTmoInfo().GetSender())
	}
	if own.GetTmoInfo().GetRound() != 1 {
		t.Fatalf("self-timeout round = %d, want 1", own.GetTmoInfo().GetRound())
	}
}

func TestProcessRemoteTimeoutQuorumFormsValidTC(t *testing.T) {
	pm, _, _, _ := newTestPacemaker(t, 4) // quorum=3
	if !pm.AdvanceRoundQC(bareQC(nil, 0)) {
		t.Fatal("setup: AdvanceRoundQC(round 0) should have entered round 1")
	}

	// Descending sender ids: a certificate's canonical signer order is a
	// property of the certificate, not of the order its parts arrived in.
	senders := []struct {
		id          uint32
		highQCRound uint64
	}{
		{4, 9},
		{3, 7},
		{2, 5},
	}
	var tc *diempb.TimeoutCert
	for _, s := range senders {
		tc = pm.ProcessRemoteTimeout(timeoutMsg(timeoutInfoFrom(t, s.id, 4, 1, s.highQCRound)))
	}
	if tc == nil {
		t.Fatal("no TC formed at quorum (3 distinct senders)")
	}
	if tc.GetRound() != 1 {
		t.Fatalf("tc.GetRound() = %d, want 1", tc.GetRound())
	}
	if len(tc.GetVotes()) != 3 {
		t.Fatalf("tc has %d votes, want 3 (quorum)", len(tc.GetVotes()))
	}

	want := map[uint32]uint64{2: 5, 3: 7, 4: 9}
	for _, v := range tc.GetVotes() {
		got, ok := want[v.GetSig().GetSigner()]
		if !ok {
			t.Fatalf("vote signed by unexpected sender %d", v.GetSig().GetSigner())
		}
		if got != v.GetHighQcRound() {
			t.Fatalf("vote for sender %d pairs HighQCRound %d, want %d (each sender's own high_qc round)",
				v.GetSig().GetSigner(), v.GetHighQcRound(), got)
		}
	}

	if !NewVerifier(newTestSigner(4), 3).VerifyTC(tc) {
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
	qc := makeQC(voteInfo(hashOf(1), 2, nil, 1), nil, 1, 2, 3)
	pm.tree.ProcessQC(qc)
	if pm.AdvanceRoundQC(qc) {
		t.Fatal("AdvanceRoundQC(QC for round 2) = true, want a certificate below the current round to change nothing")
	}

	pm.LocalTimeoutRound()

	if len(net.timeouts) != 1 {
		t.Fatalf("broadcast %d timeouts, want 1", len(net.timeouts))
	}
	if m := net.timeouts[0]; !WellFormedTimeout(m) {
		t.Fatalf("broadcast an ill-formed timeout: round %d over a high_qc for round %d, carrying a TC for round %d; every honest replica discards it",
			m.GetTmoInfo().GetRound(), QCRound(m.GetTmoInfo().GetHighQc()), m.GetLastRoundTc().GetRound())
	}
}

func TestBackoffGrowsThenResets(t *testing.T) {
	base, max, factor := 10*time.Millisecond, 80*time.Millisecond, 2.0
	d := NewBackoff(base, max, factor)

	if got := d.Duration(); got != base {
		t.Fatalf("Duration() = %v, want base %v", got, base)
	}

	want := base
	for i := range 5 {
		d.Grow()
		want = min(time.Duration(float64(want)*factor), max)
		if got := d.Duration(); got != want {
			t.Fatalf("after %d timeouts, Duration() = %v, want %v", i+1, got, want)
		}
	}
	if got := d.Duration(); got != max {
		t.Errorf("Duration() = %v, want saturated at max %v", got, max)
	}

	d.Reset()
	if got := d.Duration(); got != base {
		t.Errorf("Duration() after Reset() = %v, want base %v", got, base)
	}
}

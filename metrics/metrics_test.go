package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// fakeClock is a hand-driven hotstuff.Clock: Now returns a field the test
// advances directly, and AfterFunc is unused by this package so it returns
// nil.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time                                 { return c.now }
func (c *fakeClock) AfterFunc(time.Duration, func()) hotstuff.Timer { return nil }

// recordingTransport records every call it receives.
type recordingTransport struct {
	proposals []hotstuff.Proposal
	votes     []hotstuff.PartialCert
	timeouts  []hotstuff.TimeoutMsg
	fetches   []hotstuff.Hash
}

func (r *recordingTransport) Propose(p hotstuff.Proposal)   { r.proposals = append(r.proposals, p) }
func (r *recordingTransport) Vote(c hotstuff.PartialCert)   { r.votes = append(r.votes, c) }
func (r *recordingTransport) Timeout(t hotstuff.TimeoutMsg) { r.timeouts = append(r.timeouts, t) }
func (r *recordingTransport) Fetch(h hotstuff.Hash)         { r.fetches = append(r.fetches, h) }

// recordingExecutor records every block it receives.
type recordingExecutor struct{ execed []*hotstuff.Block }

func (r *recordingExecutor) Exec(b *hotstuff.Block) { r.execed = append(r.execed, b) }

func block(view hotstuff.View, cmds [][]byte) *hotstuff.Block {
	return hotstuff.NewBlock(hotstuff.Hash{}, view, 1, hotstuff.QuorumCert{}, cmds)
}

func TestTransportForwards(t *testing.T) {
	rt := &recordingTransport{}
	m := New(&fakeClock{}, 0)
	tr := m.Transport(rt)

	p := hotstuff.Proposal{Block: block(1, nil)}
	v := hotstuff.PartialCert{View: 1}
	to := hotstuff.TimeoutMsg{View: 1}
	h := hotstuff.Hash{1}

	tr.Propose(p)
	tr.Vote(v)
	tr.Timeout(to)
	tr.Fetch(h)

	// hotstuff.Signature embeds a []byte, so these structs aren't
	// comparable with ==: compare the fields that identify the call instead.
	if len(rt.proposals) != 1 || rt.proposals[0].Block != p.Block {
		t.Errorf("Propose not forwarded: got %v", rt.proposals)
	}
	if len(rt.votes) != 1 || rt.votes[0].View != v.View {
		t.Errorf("Vote not forwarded: got %v", rt.votes)
	}
	if len(rt.timeouts) != 1 || rt.timeouts[0].View != to.View {
		t.Errorf("Timeout not forwarded: got %v", rt.timeouts)
	}
	if len(rt.fetches) != 1 || rt.fetches[0] != h {
		t.Errorf("Fetch not forwarded: got %v", rt.fetches)
	}
}

func TestExecutorForwards(t *testing.T) {
	re := &recordingExecutor{}
	m := New(&fakeClock{}, 0)
	ex := m.Executor(re)

	b := block(1, nil)
	ex.Exec(b)

	if len(re.execed) != 1 || re.execed[0] != b {
		t.Errorf("Exec not forwarded: got %v", re.execed)
	}
}

func TestOutboundCounters(t *testing.T) {
	rt := &recordingTransport{}
	m := New(&fakeClock{}, 0)
	tr := m.Transport(rt)

	tr.Propose(hotstuff.Proposal{Block: block(1, nil)})
	tr.Vote(hotstuff.PartialCert{})
	tr.Vote(hotstuff.PartialCert{})
	tr.Timeout(hotstuff.TimeoutMsg{})
	tr.Fetch(hotstuff.Hash{})
	tr.Fetch(hotstuff.Hash{})
	tr.Fetch(hotstuff.Hash{})

	snap := m.Snapshot()
	if snap.ProposalsSent != 1 {
		t.Errorf("ProposalsSent = %d, want 1", snap.ProposalsSent)
	}
	if snap.VotesSent != 2 {
		t.Errorf("VotesSent = %d, want 2", snap.VotesSent)
	}
	if snap.TimeoutsSent != 1 {
		t.Errorf("TimeoutsSent = %d, want 1", snap.TimeoutsSent)
	}
	if snap.FetchesSent != 3 {
		t.Errorf("FetchesSent = %d, want 3", snap.FetchesSent)
	}
}

func TestEventCountersAndStepTime(t *testing.T) {
	m := New(&fakeClock{}, 0)

	events := []struct {
		e    hotstuff.Event
		took time.Duration
		key  string
	}{
		{hotstuff.ProposeEvent{}, 10 * time.Millisecond, "propose"},
		{hotstuff.VoteEvent{}, 20 * time.Millisecond, "vote"},
		{hotstuff.TimeoutEvent{}, 30 * time.Millisecond, "timeout"},
		{hotstuff.FetchedEvent{}, 40 * time.Millisecond, "fetched"},
		{hotstuff.ViewTimeoutEvent{}, 50 * time.Millisecond, "view_timeout"},
	}
	for _, ev := range events {
		m.Observe(ev.e, hotstuff.State{}, ev.took)
	}

	snap := m.Snapshot()
	if snap.ProposeEvents != 1 || snap.VoteEvents != 1 || snap.TimeoutEvents != 1 ||
		snap.FetchedEvents != 1 || snap.ViewTimeoutEvents != 1 {
		t.Errorf("event counters = %+v, want all 1", snap)
	}
	if len(snap.StepNanos) != 5 {
		t.Fatalf("StepNanos has %d keys, want exactly 5: %v", len(snap.StepNanos), snap.StepNanos)
	}
	for _, ev := range events {
		if got, want := snap.StepNanos[ev.key], uint64(ev.took); got != want {
			t.Errorf("StepNanos[%q] = %d, want %d", ev.key, got, want)
		}
	}
}

func TestDerivedCounters(t *testing.T) {
	m := New(&fakeClock{}, 0)

	states := []hotstuff.State{
		{View: 1, HighQC: hotstuff.QuorumCert{View: 1}},
		{View: 1, HighQC: hotstuff.QuorumCert{View: 1}}, // no movement: adds nothing
		{View: 2, HighQC: hotstuff.QuorumCert{View: 2}},
		{View: 5, HighQC: hotstuff.QuorumCert{View: 5}}, // jumps by more than 1: still +1
	}
	for _, s := range states {
		m.Observe(hotstuff.ProposeEvent{}, s, 0)
	}

	snap := m.Snapshot()
	if snap.ViewsEntered != 3 {
		t.Errorf("ViewsEntered = %d, want 3 (transitions counted, not view distance)", snap.ViewsEntered)
	}
	if snap.QCsFormed != 3 {
		t.Errorf("QCsFormed = %d, want 3 (transitions counted, not view distance)", snap.QCsFormed)
	}
	if snap.View != 5 {
		t.Errorf("View = %d, want 5", snap.View)
	}
}

func TestCommitLatencyEndToEnd(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	m := New(clock, 0)
	rt := &recordingTransport{}
	re := &recordingExecutor{}
	tr := m.Transport(rt)
	ex := m.Executor(re)

	b1 := block(1, nil)
	tr.Propose(hotstuff.Proposal{Block: b1})
	clock.now = clock.now.Add(100 * time.Millisecond)
	ex.Exec(b1)

	snap := m.Snapshot()
	if snap.LatencySamples != 1 {
		t.Fatalf("LatencySamples = %d, want 1", snap.LatencySamples)
	}
	if snap.LatencyTotalNs != uint64(100*time.Millisecond) {
		t.Errorf("LatencyTotalNs = %d, want %d", snap.LatencyTotalNs, uint64(100*time.Millisecond))
	}
	if snap.LatencyMaxNs != uint64(100*time.Millisecond) {
		t.Errorf("LatencyMaxNs = %d, want %d", snap.LatencyMaxNs, uint64(100*time.Millisecond))
	}

	b2 := block(2, nil)
	tr.Propose(hotstuff.Proposal{Block: b2})
	clock.now = clock.now.Add(300 * time.Millisecond)
	ex.Exec(b2)

	snap = m.Snapshot()
	if snap.LatencySamples != 2 {
		t.Fatalf("LatencySamples = %d, want 2", snap.LatencySamples)
	}
	if snap.LatencyMaxNs != uint64(300*time.Millisecond) {
		t.Errorf("LatencyMaxNs = %d, want max of the two samples %d", snap.LatencyMaxNs, uint64(300*time.Millisecond))
	}

	// A block executed without having been proposed adds no sample.
	b3 := block(3, nil)
	ex.Exec(b3)
	snap = m.Snapshot()
	if snap.LatencySamples != 2 {
		t.Errorf("LatencySamples = %d after unproposed Exec, want still 2", snap.LatencySamples)
	}
}

func TestLatencyMapBounded(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	m := New(clock, 2)
	rt := &recordingTransport{}
	tr := m.Transport(rt)

	tr.Propose(hotstuff.Proposal{Block: block(1, nil)})
	tr.Propose(hotstuff.Proposal{Block: block(2, nil)})
	tr.Propose(hotstuff.Proposal{Block: block(3, nil)}) // hits the cap, clears the map

	if len(m.proposedAt) != 1 {
		t.Errorf("proposedAt has %d entries after clearing, want 1 (just the block that tripped the cap)", len(m.proposedAt))
	}
	snap := m.Snapshot()
	if snap.LatencyDropped != 2 {
		t.Errorf("LatencyDropped = %d, want 2", snap.LatencyDropped)
	}
}

func TestCommandsExec(t *testing.T) {
	m := New(&fakeClock{}, 0)
	re := &recordingExecutor{}
	ex := m.Executor(re)

	ex.Exec(block(1, [][]byte{[]byte("a"), []byte("b")}))
	ex.Exec(block(2, [][]byte{[]byte("c")}))

	snap := m.Snapshot()
	if snap.CommandsExec != 3 {
		t.Errorf("CommandsExec = %d, want 3", snap.CommandsExec)
	}
	if snap.Committed != 2 {
		t.Errorf("Committed = %d, want 2", snap.Committed)
	}
}

// notifyWriter wraps a buffer and signals on wrote after every Write, so a
// test can wait for a given number of lines without sleeping.
type notifyWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	wrote chan struct{}
}

func newNotifyWriter() *notifyWriter { return &notifyWriter{wrote: make(chan struct{}, 1)} }

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func (w *notifyWriter) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func TestSampleWritesNDJSON(t *testing.T) {
	m := New(&fakeClock{}, 0)
	rt := &recordingTransport{}
	tr := m.Transport(rt)
	tr.Propose(hotstuff.Proposal{Block: block(1, nil)})

	w := newNotifyWriter()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Sample(ctx, w, time.Millisecond) }()

	// Wait for two ticks to actually land, via the writer's notifications —
	// not a sleep — before cancelling.
	const wantTicks = 2
	for i := 0; i < wantTicks; i++ {
		select {
		case <-w.wrote:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for tick %d", i+1)
		}
	}
	cancel()
	err := <-done
	if err != context.Canceled {
		t.Fatalf("Sample returned %v, want context.Canceled", err)
	}

	lines := bytes.Split(bytes.TrimRight(w.snapshot(), "\n"), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		t.Fatalf("Sample wrote no lines")
	}
	var last Snapshot
	for _, line := range lines {
		var snap Snapshot
		if err := json.Unmarshal(line, &snap); err != nil {
			t.Fatalf("line %q did not parse as Snapshot: %v", line, err)
		}
		last = snap
	}

	want := m.Snapshot()
	if last.ProposalsSent != want.ProposalsSent {
		t.Errorf("last line ProposalsSent = %d, want %d", last.ProposalsSent, want.ProposalsSent)
	}
}

func TestSampleRejectsZeroInterval(t *testing.T) {
	m := New(&fakeClock{}, 0)
	var buf bytes.Buffer
	if err := m.Sample(context.Background(), &buf, 0); err == nil {
		t.Error("Sample with interval 0: want error, got nil")
	}
}

func TestSnapshotRaceSafe(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	m := New(clock, 0)
	rt := &recordingTransport{}
	re := &recordingExecutor{}
	tr := m.Transport(rt)
	ex := m.Executor(re)

	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			b := block(hotstuff.View(i), nil)
			tr.Propose(hotstuff.Proposal{Block: b})
			m.Observe(hotstuff.ProposeEvent{}, hotstuff.State{View: hotstuff.View(i)}, time.Microsecond)
			ex.Exec(b)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = m.Snapshot()
		}
	}()
	wg.Wait()
}

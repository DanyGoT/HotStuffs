// Package metrics instruments a replica from the outside. It never changes
// the protocol: it decorates the Transport and Executor seams and hooks the
// core's single observer callback. Between them those three see every
// message sent, every block committed, and every event stepped.
package metrics

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// defaultLatencyCap bounds the in-flight propose-time map when New is given 0.
const defaultLatencyCap = 4096

// latency is the commit-latency measurement so far: how many samples went
// into it and what they sum to. The two only mean anything together.
type latency struct {
	samples uint64
	totalNs uint64
}

// Metrics counts what a replica did. Construct one, wrap the two seams with
// it, pass Observe as the core's observer, and read Snapshot from anywhere.
type Metrics struct {
	clock      hotstuff.Clock
	latencyCap int

	proposalsSent atomic.Uint64
	votesSent     atomic.Uint64
	timeoutsSent  atomic.Uint64
	fetchesSent   atomic.Uint64

	proposeEvents     atomic.Uint64
	voteEvents        atomic.Uint64
	timeoutEvents     atomic.Uint64
	fetchedEvents     atomic.Uint64
	viewTimeoutEvents atomic.Uint64

	qcsFormed    atomic.Uint64
	viewsEntered atomic.Uint64

	committed     atomic.Uint64
	commandsExec  atomic.Uint64
	view          atomic.Uint64
	committedView atomic.Uint64

	stepProposeNanos     atomic.Uint64
	stepVoteNanos        atomic.Uint64
	stepTimeoutNanos     atomic.Uint64
	stepFetchedNanos     atomic.Uint64
	stepViewTimeoutNanos atomic.Uint64

	// latency holds the sample count and the running total together, so a
	// reader can never pair a count with a total from a different moment and
	// report a mean that neither of them ever produced.
	latency        atomic.Pointer[latency]
	latencyMaxNs   atomic.Uint64
	latencyDropped atomic.Uint64

	// proposedAt is touched only by Transport.Propose and Executor.Exec, both
	// called from the single consensus goroutine in order: no lock needed.
	proposedAt map[hotstuff.Hash]time.Time

	// lastHighQCView and lastView are likewise touched only from Observe,
	// called from the single consensus goroutine: no lock needed.
	lastHighQCView hotstuff.View
	lastView       hotstuff.View
}

// New returns a Metrics reading time from clock. latencyCap bounds the
// in-flight propose-time map; 0 picks a default.
func New(clock hotstuff.Clock, latencyCap int) *Metrics {
	if latencyCap == 0 {
		latencyCap = defaultLatencyCap
	}
	return &Metrics{
		clock:      clock,
		latencyCap: latencyCap,
		proposedAt: make(map[hotstuff.Hash]time.Time),
	}
}

// transport decorates a hotstuff.Transport, counting what goes out and
// noting when each block this replica proposed was sent.
type transport struct {
	m *Metrics
	t hotstuff.Transport
}

// Transport decorates t: it counts what goes out, and notes when each block
// this replica proposed was sent, which is half of the commit latency
// measurement. t must not be nil.
func (m *Metrics) Transport(t hotstuff.Transport) hotstuff.Transport {
	if t == nil {
		panic("metrics: Transport requires a non-nil hotstuff.Transport")
	}
	return &transport{m: m, t: t}
}

func (d *transport) Propose(p hotstuff.Proposal) {
	d.m.proposalsSent.Add(1)
	d.m.noteProposed(p.Block.Hash())
	d.t.Propose(p)
}

func (d *transport) Vote(c hotstuff.PartialCert) {
	d.m.votesSent.Add(1)
	d.t.Vote(c)
}

func (d *transport) Timeout(t hotstuff.TimeoutMsg) {
	d.m.timeoutsSent.Add(1)
	d.t.Timeout(t)
}

func (d *transport) Fetch(h hotstuff.Hash) {
	d.m.fetchesSent.Add(1)
	d.t.Fetch(h)
}

// noteProposed records when a block this replica proposed was sent. If the
// in-flight map is at its cap, it is cleared entirely and the discarded
// entries are counted as dropped: forks that never commit would otherwise
// leak the map's memory forever.
func (m *Metrics) noteProposed(h hotstuff.Hash) {
	if len(m.proposedAt) >= m.latencyCap {
		m.latencyDropped.Add(uint64(len(m.proposedAt)))
		m.proposedAt = make(map[hotstuff.Hash]time.Time)
	}
	m.proposedAt[h] = m.clock.Now()
}

// executor decorates a hotstuff.Executor, counting commits and closing the
// latency measurement Transport opened.
type executor struct {
	m *Metrics
	e hotstuff.Executor
}

// Executor decorates e: it counts commits and closes the latency measurement
// Transport opened. e must not be nil.
func (m *Metrics) Executor(e hotstuff.Executor) hotstuff.Executor {
	if e == nil {
		panic("metrics: Executor requires a non-nil hotstuff.Executor")
	}
	return &executor{m: m, e: e}
}

func (d *executor) Exec(b *hotstuff.Block) {
	d.m.committed.Add(1)
	d.m.commandsExec.Add(uint64(len(b.Cmds())))
	d.m.noteExecuted(b.Hash())
	d.e.Exec(b)
}

// noteExecuted closes the latency measurement for a block this replica
// proposed. A block this replica did not propose has no entry, which is
// correct: latency is measured leader-side only.
func (m *Metrics) noteExecuted(h hotstuff.Hash) {
	t, ok := m.proposedAt[h]
	if !ok {
		return
	}
	delete(m.proposedAt, h)
	took := uint64(m.clock.Now().Sub(t))
	// Written only from the consensus goroutine, so a load and a store is all
	// the update needs; the atomic is for the readers.
	next := latency{samples: 1, totalNs: took}
	if cur := m.latency.Load(); cur != nil {
		next = latency{samples: cur.samples + 1, totalNs: cur.totalNs + took}
	}
	m.latency.Store(&next)
	for {
		high := m.latencyMaxNs.Load()
		if took <= high || m.latencyMaxNs.CompareAndSwap(high, took) {
			break
		}
	}
}

// Observe is the core's Observer hook: it counts events by type, sums how
// long Step took for each, and derives the protocol counters from the state
// snapshot.
func (m *Metrics) Observe(e hotstuff.Event, s hotstuff.State, took time.Duration) {
	switch e.(type) {
	case hotstuff.ProposeEvent:
		m.proposeEvents.Add(1)
		m.stepProposeNanos.Add(uint64(took))
	case hotstuff.VoteEvent:
		m.voteEvents.Add(1)
		m.stepVoteNanos.Add(uint64(took))
	case hotstuff.TimeoutEvent:
		m.timeoutEvents.Add(1)
		m.stepTimeoutNanos.Add(uint64(took))
	case hotstuff.FetchedEvent:
		m.fetchedEvents.Add(1)
		m.stepFetchedNanos.Add(uint64(took))
	case hotstuff.ViewTimeoutEvent:
		m.viewTimeoutEvents.Add(1)
		m.stepViewTimeoutNanos.Add(uint64(took))
	}

	// QCsFormed and ViewsEntered are derived from the state snapshot rather
	// than counted in the core, which is what keeps the core free of
	// instrumentation. Each counts transitions, so a jump of more than one
	// still adds exactly 1.
	if s.HighQC.View > m.lastHighQCView {
		m.lastHighQCView = s.HighQC.View
		m.qcsFormed.Add(1)
	}
	if s.View > m.lastView {
		m.lastView = s.View
		m.viewsEntered.Add(1)
	}

	m.view.Store(uint64(s.View))
	m.committedView.Store(uint64(s.CommittedView))
}

// Snapshot is a point-in-time copy of every counter.
type Snapshot struct {
	Time time.Time `json:"time"`

	ProposalsSent uint64 `json:"proposals_sent"`
	VotesSent     uint64 `json:"votes_sent"`
	TimeoutsSent  uint64 `json:"timeouts_sent"`
	FetchesSent   uint64 `json:"fetches_sent"`

	ProposeEvents     uint64 `json:"propose_events"`
	VoteEvents        uint64 `json:"vote_events"`
	TimeoutEvents     uint64 `json:"timeout_events"`
	FetchedEvents     uint64 `json:"fetched_events"`
	ViewTimeoutEvents uint64 `json:"view_timeout_events"`

	QCsFormed    uint64 `json:"qcs_formed"`
	ViewsEntered uint64 `json:"views_entered"`

	Committed     uint64 `json:"committed"`     // blocks executed
	CommandsExec  uint64 `json:"commands_exec"` // commands inside them
	View          uint64 `json:"view"`
	CommittedView uint64 `json:"committed_view"`

	// StepNanos totals the time Step spent on each event type, keyed by the
	// type's short name ("propose", "vote", "timeout", "fetched",
	// "view_timeout").
	StepNanos map[string]uint64 `json:"step_nanos"`

	// Commit latency, leader-side only: a replica measures the blocks it
	// proposed itself, from Propose to Exec.
	LatencySamples uint64 `json:"latency_samples"`
	LatencyTotalNs uint64 `json:"latency_total_ns"`
	LatencyMaxNs   uint64 `json:"latency_max_ns"`
	// LatencyDropped counts blocks whose propose time was discarded because
	// the in-flight map hit its cap — forks that never commit would
	// otherwise leak.
	LatencyDropped uint64 `json:"latency_dropped"`
}

// Snapshot copies every counter. It is safe to call from any goroutine, which
// is why it stamps the wall clock rather than the injected one: the Clock seam
// belongs to the consensus goroutine.
func (m *Metrics) Snapshot() Snapshot {
	var lat latency
	if cur := m.latency.Load(); cur != nil {
		lat = *cur
	}
	return Snapshot{
		Time: time.Now(),

		ProposalsSent: m.proposalsSent.Load(),
		VotesSent:     m.votesSent.Load(),
		TimeoutsSent:  m.timeoutsSent.Load(),
		FetchesSent:   m.fetchesSent.Load(),

		ProposeEvents:     m.proposeEvents.Load(),
		VoteEvents:        m.voteEvents.Load(),
		TimeoutEvents:     m.timeoutEvents.Load(),
		FetchedEvents:     m.fetchedEvents.Load(),
		ViewTimeoutEvents: m.viewTimeoutEvents.Load(),

		QCsFormed:    m.qcsFormed.Load(),
		ViewsEntered: m.viewsEntered.Load(),

		Committed:     m.committed.Load(),
		CommandsExec:  m.commandsExec.Load(),
		View:          m.view.Load(),
		CommittedView: m.committedView.Load(),

		StepNanos: map[string]uint64{
			"propose":      m.stepProposeNanos.Load(),
			"vote":         m.stepVoteNanos.Load(),
			"timeout":      m.stepTimeoutNanos.Load(),
			"fetched":      m.stepFetchedNanos.Load(),
			"view_timeout": m.stepViewTimeoutNanos.Load(),
		},

		LatencySamples: lat.samples,
		LatencyTotalNs: lat.totalNs,
		LatencyMaxNs:   m.latencyMaxNs.Load(),
		LatencyDropped: m.latencyDropped.Load(),
	}
}

// LogValue lets a Snapshot be logged with slog without a custom formatter.
func (s Snapshot) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Time("time", s.Time),
		slog.Uint64("proposals_sent", s.ProposalsSent),
		slog.Uint64("votes_sent", s.VotesSent),
		slog.Uint64("timeouts_sent", s.TimeoutsSent),
		slog.Uint64("fetches_sent", s.FetchesSent),
		slog.Uint64("propose_events", s.ProposeEvents),
		slog.Uint64("vote_events", s.VoteEvents),
		slog.Uint64("timeout_events", s.TimeoutEvents),
		slog.Uint64("fetched_events", s.FetchedEvents),
		slog.Uint64("view_timeout_events", s.ViewTimeoutEvents),
		slog.Uint64("qcs_formed", s.QCsFormed),
		slog.Uint64("views_entered", s.ViewsEntered),
		slog.Uint64("committed", s.Committed),
		slog.Uint64("commands_exec", s.CommandsExec),
		slog.Uint64("view", s.View),
		slog.Uint64("committed_view", s.CommittedView),
		slog.Uint64("latency_samples", s.LatencySamples),
		slog.Uint64("latency_total_ns", s.LatencyTotalNs),
		slog.Uint64("latency_max_ns", s.LatencyMaxNs),
		slog.Uint64("latency_dropped", s.LatencyDropped),
	)
}

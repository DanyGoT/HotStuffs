package diem

import (
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Core is the paper's Main module (3.1): the event loop that dispatches
// messages to the other modules. It owns all protocol state and runs on a
// single goroutine, so it holds no locks, and it never enqueues — every
// self-addressed message goes out through the transport's local node.
type Core struct {
	id     ID
	crypto Crypto
	net    Transport
	clock  Clock

	transactions func() [][]byte

	tree      *BlockTree
	safety    *Safety
	pacemaker *Pacemaker
	leaders   *LeaderElection

	observe func(Event, State, time.Duration)
}

// Config is everything a Core needs. Every field is required except
// Transactions, Observer, WindowSize and ExcludeSize.
type Config struct {
	ID         ID
	Validators []ID
	Ledger     *MemLedger
	Crypto     Crypto
	Transport  Transport
	Clock      Clock
	Duration   *hotstuff.Duration

	// Sink accepts events from any goroutine. Only the round timer uses it:
	// its callback runs off the consensus goroutine, so it may enqueue and
	// nothing else. Production passes Queue.Push.
	Sink func(Event)

	// Transactions supplies the payload for a leader's proposal (paper 3.6).
	// Nil proposes empty blocks, which still commits the pipeline below them.
	Transactions func() [][]byte

	// WindowSize is how far back LeaderElection reads the active set;
	// ExcludeSize is how many recent commit authors it holds out, which the
	// paper puts between f and 2f. Zero picks the defaults below.
	WindowSize  int
	ExcludeSize int

	// Observer, if set, runs after every event with the state it produced and
	// how long the step took. It is the only hook the core exposes, and it is
	// enough: every protocol-level counter is a delta on that snapshot.
	Observer func(Event, State, time.Duration)
}

// State is the scalar snapshot an observer sees.
type State struct {
	Round            Round
	HighQCRound      Round
	HighCommitRound  Round
	HighestVoteRound Round
	HighestQCRound   Round

	// DeclinedMissingAncestor is monotonic. A rate taken over it is the rate at
	// which this replica lost a vote to a gap in its own chain, which is the
	// standing cost of the paper having no block-sync.
	DeclinedMissingAncestor uint64
}

// New wires the modules together. The dependency order is the paper's: the
// block tree stands on the ledger, Safety on the block tree, the Pacemaker on
// both, and LeaderElection on the Pacemaker's round.
func New(cfg Config) *Core {
	n := len(cfg.Validators)
	quorum := hotstuff.QuorumSize(n)
	faulty := hotstuff.Faulty(n)

	window, exclude := cfg.WindowSize, cfg.ExcludeSize
	if window == 0 {
		window = defaultWindowSize
	}
	if exclude == 0 {
		exclude = max(faulty, 1)
	}

	tree := NewBlockTree(cfg.ID, quorum, cfg.Ledger, cfg.Crypto)
	safety := NewSafety(cfg.ID, NewVerifier(cfg.Crypto, quorum), cfg.Crypto, cfg.Ledger, tree)
	pacemaker := NewPacemaker(quorum, faulty, cfg.Clock, cfg.Duration, cfg.Sink, cfg.Transport, safety, tree)
	leaders := NewLeaderElection(cfg.Validators, window, exclude, cfg.Ledger, pacemaker)

	return &Core{
		id:     cfg.ID,
		crypto: cfg.Crypto,
		net:    cfg.Transport,
		clock:  cfg.Clock,

		transactions: cfg.Transactions,

		tree:      tree,
		safety:    safety,
		pacemaker: pacemaker,
		leaders:   leaders,
		observe:   cfg.Observer,
	}
}

// defaultWindowSize is how many committed blocks the reputation scheme reads
// back over. Large enough that a replica missing from the active set really
// has been quiet, small enough to stay inside the ledger's retention.
const defaultWindowSize = 10

// maxRoundLead is how far ahead of the current round an inbound vote may claim
// before this replica stops accumulating it. A vote is bucketed by the digest
// of a LedgerCommitInfo its sender picks freely, and nothing a receiver can
// check binds the round it claims to anything, so one sender opens one bucket
// per message and only a commit — needing a quorum those votes can never
// reach — would prune them. A round no certificate has been seen for is a round
// nothing can be aggregated in anyway, and catching up does not depend on these
// votes: a certificate rides on every proposal and every timeout.
const maxRoundLead = 4

// Start enters round 1 on the genesis certificate and arms the round timer.
// The paper leaves bootstrap unspecified; this is the smallest thing that
// gives round 1 a leader and a parent to extend.
func (c *Core) Start() {
	c.pacemaker.AdvanceRoundQC(genesisQC)
	c.processNewRoundEvent(nil)
}

// Stop disarms the round timer.
func (c *Core) Stop() { c.pacemaker.Stop() }

// State is the scalar snapshot of this replica's progress.
func (c *Core) State() State {
	return State{
		Round:            c.pacemaker.CurrentRound(),
		HighQCRound:      c.tree.HighQC().Round(),
		HighCommitRound:  c.tree.HighCommitQC().Round(),
		HighestVoteRound: c.safety.HighestVoteRound(),
		HighestQCRound:   c.safety.HighestQCRound(),

		DeclinedMissingAncestor: c.safety.DeclinedMissingAncestor(),
	}
}

// Step is the whole protocol surface — the paper's start_event_processing. The
// event set is sealed, so this switch is exhaustive and needs no default.
func (c *Core) Step(e Event) {
	if c.observe != nil {
		start := c.clock.Now()
		defer func() { c.observe(e, c.State(), c.clock.Now().Sub(start)) }()
	}
	switch e := e.(type) {
	case ProposalEvent:
		c.processProposalMsg(e.Msg)
	case VoteEvent:
		c.processVoteMsg(e.Msg)
	case TimeoutEvent:
		c.processTimeoutMsg(e.Msg)
	case LocalTimeoutEvent:
		// The paper dispatches this unconditionally (3.1, start_event_processing:
		// local timeout -> Pacemaker.local_timeout_round()). The round is checked
		// first because the timer callback runs off this goroutine and only
		// enqueues: a callback that had already fired when startTimer or Stop
		// disarmed the timer is still sitting in the queue, and running it would
		// abandon a round the replica has since entered on a perfectly good
		// certificate.
		if e.Round == c.pacemaker.CurrentRound() {
			c.pacemaker.LocalTimeoutRound()
		}
	}
}

// processCertificateQC is the paper's process_certificate_qc. The order
// matters: LeaderElection reads the round the certificate arrived in, so it
// must run before the Pacemaker advances past it.
func (c *Core) processCertificateQC(qc *QC) {
	if qc == nil {
		return
	}
	c.tree.ProcessQC(qc)
	c.leaders.UpdateLeaders(qc)
	c.pacemaker.AdvanceRoundQC(qc)
}

// processProposalMsg is the paper's process_proposal_msg. Authentication has
// already happened at the edge, on the goroutine the message arrived on, so
// what is left here is authorization by protocol state.
func (c *Core) processProposalMsg(p *ProposalMsg) {
	c.processCertificateQC(p.Block.QC)
	c.processCertificateQC(p.HighCommitQC)
	c.pacemaker.AdvanceRoundTC(p.LastRoundTC)

	// The one message check that cannot move to the edge: GetLeader (3.7) reads
	// the committed blocks for its reputation path, so who leads a round is a
	// function of protocol state, not of the round number.
	round := c.pacemaker.CurrentRound()
	leader := c.leaders.GetLeader(round)
	if p.Block.Round != round || p.Sender != leader || p.Block.Author != leader {
		return
	}

	c.tree.ExecuteAndInsert(p.Block)
	vote := c.safety.MakeVote(p.Block, p.LastRoundTC)
	if vote == nil {
		return
	}
	// A vote is unicast to the next round's leader, which is the only replica
	// that can use it: it is the one that will propose over the certificate.
	c.net.Vote(vote, c.leaders.GetLeader(round+1))
}

func (c *Core) processTimeoutMsg(m *TimeoutMsg) {
	c.processCertificateQC(m.TmoInfo.HighQC)
	c.processCertificateQC(m.HighCommitQC)
	c.pacemaker.AdvanceRoundTC(m.LastRoundTC)

	tc := c.pacemaker.ProcessRemoteTimeout(m)
	if tc == nil {
		return
	}
	c.pacemaker.AdvanceRoundTC(tc)
	c.processNewRoundEvent(tc)
}

func (c *Core) processVoteMsg(m *VoteMsg) {
	if m.VoteInfo.Round > c.pacemaker.CurrentRound()+maxRoundLead {
		return
	}
	qc := c.tree.ProcessVote(m)
	if qc == nil {
		return
	}
	c.processCertificateQC(qc)
	c.processNewRoundEvent(nil)
}

// processNewRoundEvent proposes, if this replica leads the round it just
// entered. Note that entering a round on a proposal's certificate does not
// come through here: the leader of round r+1 proposes once it has assembled
// the certificate for round r itself, which is what pipelines the two.
func (c *Core) processNewRoundEvent(lastTC *TC) {
	round := c.pacemaker.CurrentRound()
	if c.leaders.GetLeader(round) != c.id {
		return
	}
	var txns [][]byte
	if c.transactions != nil {
		txns = c.transactions()
	}
	b := c.tree.GenerateBlock(txns, round)
	sig, err := c.crypto.Sign(b.ID())
	if err != nil {
		return
	}
	c.net.Proposal(&ProposalMsg{
		Block:        b,
		LastRoundTC:  justifyingTC(b.QC.Round(), round, lastTC),
		HighCommitQC: c.tree.HighCommitQC(),
		Sender:       c.id,
		Sig:          sig,
	})
}

// justifyingTC drops a TC the block's own certificate already justifies. A
// proposal carrying a redundant TC is ill-formed by the paper's rule and every
// honest replica would discard it.
func justifyingTC(qcRound, round Round, tc *TC) *TC {
	if qcRound+1 == round {
		return nil
	}
	return tc
}

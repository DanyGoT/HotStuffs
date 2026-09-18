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
	pool   MemPool
	clock  Clock

	tree      *BlockTree
	safety    *Safety
	pacemaker *Pacemaker
	leaders   *LeaderElection

	observe func(Event, State, time.Duration)
}

// Config is everything a Core needs. Every field is required except Observer,
// WindowSize and ExcludeSize.
type Config struct {
	ID         ID
	Validators []ID
	Ledger     Ledger
	MemPool    MemPool
	Crypto     Crypto
	Transport  Transport
	Clock      Clock
	Duration   RoundDuration
	Sink       EventSink

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
	safety := NewSafety(cfg.ID, quorum, cfg.Crypto, cfg.Ledger, tree)
	pacemaker := NewPacemaker(quorum, faulty, cfg.Clock, cfg.Duration, cfg.Sink, cfg.Transport, safety, tree)
	leaders := NewLeaderElection(cfg.Validators, window, exclude, cfg.Ledger, pacemaker)

	return &Core{
		id:        cfg.ID,
		crypto:    cfg.Crypto,
		net:       cfg.Transport,
		pool:      cfg.MemPool,
		clock:     cfg.Clock,
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

func (c *Core) processProposalMsg(p *ProposalMsg) {
	// Well-formedness and signatures are checked before anything is allowed to
	// touch state. The paper leaves this to "other parts of the system"; here
	// it is the event loop, and Safety checks again on its own behalf.
	if !p.WellFormed() || !c.validProposal(p) {
		return
	}
	c.processCertificateQC(p.Block.QC)
	c.processCertificateQC(p.HighCommitQC)
	c.pacemaker.AdvanceRoundTC(p.LastRoundTC)

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
	if !m.WellFormed() || !c.validTimeout(m) {
		return
	}
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
	if !c.validVote(m) {
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
	b := c.tree.GenerateBlock(c.pool.GetTransactions(), round)
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

func (c *Core) validProposal(p *ProposalMsg) bool {
	if p.Sig.Signer != p.Sender || !c.crypto.Verify(p.Block.ID(), p.Sig) {
		return false
	}
	return c.safety.ValidQC(p.Block.QC) && c.validCommitQC(p.HighCommitQC) && c.safety.ValidTC(p.LastRoundTC)
}

func (c *Core) validTimeout(m *TimeoutMsg) bool {
	t := m.TmoInfo
	if t.Sig.Signer != t.Sender || !c.crypto.Verify(TimeoutDigest(t.Round, t.HighQC.Round()), t.Sig) {
		return false
	}
	return c.safety.ValidQC(t.HighQC) && c.validCommitQC(m.HighCommitQC) && c.safety.ValidTC(m.LastRoundTC)
}

func (c *Core) validVote(m *VoteMsg) bool {
	if m.Sig.Signer != m.Sender {
		return false
	}
	// The vote signs the LedgerCommitInfo alone, so the VoteInfo it ships with
	// is only authenticated through the hash inside it.
	if VoteInfoHash(m.VoteInfo) != m.LedgerCommitInfo.VoteInfoHash {
		return false
	}
	if !c.crypto.Verify(LedgerCommitDigest(m.LedgerCommitInfo), m.Sig) {
		return false
	}
	return c.validCommitQC(m.HighCommitQC)
}

// validCommitQC accepts an absent commit certificate: it is a catch-up hint,
// not evidence anything depends on.
func (c *Core) validCommitQC(qc *QC) bool { return qc == nil || c.safety.ValidQC(qc) }

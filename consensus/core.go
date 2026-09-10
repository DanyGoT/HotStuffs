package consensus

import (
	"cmp"
	"slices"
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Config is everything a Core needs. Every field is required.
type Config struct {
	ID        hotstuff.ID
	N         int
	Rules     hotstuff.Rules
	Store     hotstuff.BlockStore
	Crypto    hotstuff.Crypto
	Transport hotstuff.Transport
	Leader    hotstuff.LeaderRotation
	Clock     hotstuff.Clock
	Duration  hotstuff.ViewDuration
	Commands  hotstuff.CommandQueue
	Executor  hotstuff.Executor
	Sink      hotstuff.EventSink

	// Observer, if set, is called after every event with the state it produced
	// and how long Step took. It is the only hook the core exposes, and it is
	// enough: every protocol-level counter is a delta on that snapshot, so
	// instrumentation needs no wrapper around the state machine.
	Observer func(hotstuff.Event, hotstuff.State, time.Duration)
}

// fetchRetryViews is how many views a gap stays marked in-flight before it may
// be asked for again. A failed backfill reports nothing — a call error, a
// decode error and a wrong block all answer with silence — so the view number
// is the only clock this recovery has. Four covers the default fetch timeout
// at the default view duration, and asking twice would only cost a duplicate
// answer in any case: the responder serves it from its store, by hash.
const fetchRetryViews = 4

// voteKey buckets votes by the exact thing their signatures cover. Keying by
// block hash alone would let a vote claiming a different view for the same
// block join an honest quorum, and the certificate that formed would carry
// signatures over two digests and fail this replica's own VerifyQC. The view
// is in the key, so pruning needs no store lookup either.
type voteKey struct {
	view hotstuff.View
	hash hotstuff.Hash
}

// Core is the protocol state machine. It owns all protocol state and runs on a
// single goroutine, so it holds no locks, and it never enqueues: every
// self-directed action is a direct call and every self-addressed network
// message goes out through the transport's local node.
type Core struct {
	id     hotstuff.ID
	quorum int

	rules   hotstuff.Rules
	store   hotstuff.BlockStore
	crypto  hotstuff.Crypto
	net     hotstuff.Transport
	leader  hotstuff.LeaderRotation
	clock   hotstuff.Clock
	dur     hotstuff.ViewDuration
	cmds    hotstuff.CommandQueue
	exec    hotstuff.Executor
	sink    hotstuff.EventSink
	observe func(hotstuff.Event, hotstuff.State, time.Duration)

	view          hotstuff.View
	lastVotedView hotstuff.View
	lockedView    hotstuff.View
	committedView hotstuff.View
	committedHash hotstuff.Hash
	highQC        hotstuff.QuorumCert

	votes    map[voteKey][]hotstuff.Signature
	timeouts map[hotstuff.View][]hotstuff.Signature
	fetching map[hotstuff.Hash]hotstuff.View // gap hash to the view its request went out in
	pending  *hotstuff.Block                 // block whose commit check is waiting on a fetch

	timer hotstuff.Timer
}

// New builds a Core at view 0 with genesis committed.
func New(cfg Config) *Core {
	return &Core{
		id:            cfg.ID,
		quorum:        hotstuff.QuorumSize(cfg.N),
		rules:         cfg.Rules,
		store:         cfg.Store,
		crypto:        cfg.Crypto,
		net:           cfg.Transport,
		leader:        cfg.Leader,
		clock:         cfg.Clock,
		dur:           cfg.Duration,
		cmds:          cfg.Commands,
		exec:          cfg.Executor,
		sink:          cfg.Sink,
		observe:       cfg.Observer,
		committedHash: hotstuff.GenesisHash(),
		highQC:        hotstuff.QuorumCert{BlockHash: hotstuff.GenesisHash()},
		votes:         map[voteKey][]hotstuff.Signature{},
		timeouts:      map[hotstuff.View][]hotstuff.Signature{},
		fetching:      map[hotstuff.Hash]hotstuff.View{},
	}
}

// Start enters view 1 on the genesis QC and arms the view timer.
func (c *Core) Start() { c.advanceView(hotstuff.SyncInfo{QC: c.highQC}) }

// Stop disarms the view timer.
func (c *Core) Stop() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

// State is the scalar snapshot the rules see.
func (c *Core) State() hotstuff.State {
	return hotstuff.State{
		View:          c.view,
		LastVotedView: c.lastVotedView,
		LockedView:    c.lockedView,
		CommittedView: c.committedView,
		HighQC:        c.highQC,
	}
}

// Step is the whole protocol surface. The event set is sealed, so this switch
// is exhaustive and needs no default.
func (c *Core) Step(e hotstuff.Event) {
	if c.observe != nil {
		start := c.clock.Now()
		defer func() { c.observe(e, c.State(), c.clock.Now().Sub(start)) }()
	}
	switch e := e.(type) {
	case hotstuff.ProposeEvent:
		c.onPropose(e)
	case hotstuff.VoteEvent:
		c.onVote(e)
	case hotstuff.TimeoutEvent:
		c.onTimeout(e)
	case hotstuff.FetchedEvent:
		c.onFetched(e)
	case hotstuff.ViewTimeoutEvent:
		c.onViewTimeout(e)
	}
}

func (c *Core) onPropose(e hotstuff.ProposeEvent) {
	b := e.Block
	c.store.Put(b)
	// A proposal for a view already left behind is still evidence: its QC may
	// be newer than ours, which is how a replica catches up after a partition.
	if b.View() < c.view {
		c.updateHighQC(b.QC())
		return
	}
	if c.rules.VoteRule(c.State(), e.Proposal) {
		c.vote(b)
	}
	// Algorithm 4 decides the vote against the old lock, then raises it.
	c.updateLock(b.QC())
	c.commit(b)
	c.advanceView(hotstuff.SyncInfo{QC: b.QC(), TC: e.TC})
}

func (c *Core) vote(b *hotstuff.Block) {
	sig, err := c.crypto.Sign(hotstuff.VoteDigest(b.View(), b.Hash()))
	if err != nil {
		return
	}
	c.lastVotedView = b.View()
	// A vote is not a reply to the proposal — it is produced asynchronously and
	// every replica collects it. GORUMS: vote collection is a quorum the
	// primitive cannot express, since a quorum call's collector is the caller
	// and votes are keyed to a block rather than to a request.
	c.net.Vote(hotstuff.PartialCert{View: b.View(), BlockHash: b.Hash(), Sig: sig})
}

func (c *Core) onVote(e hotstuff.VoteEvent) {
	// At most one block per view can obtain a QC, so a QC at or above this
	// view already makes these votes useless.
	if e.View <= c.highQC.View {
		return
	}
	k := voteKey{view: e.View, hash: e.BlockHash}
	sigs := c.votes[k]
	if slices.ContainsFunc(sigs, func(s hotstuff.Signature) bool { return s.Signer == e.Sig.Signer }) {
		return
	}
	sigs = append(sigs, e.Sig)
	c.votes[k] = sigs
	if len(sigs) < c.quorum {
		return
	}
	qc := hotstuff.QuorumCert{View: e.View, BlockHash: e.BlockHash, Sigs: canonical(sigs)}
	c.advanceView(hotstuff.SyncInfo{QC: qc})
}

func (c *Core) onTimeout(e hotstuff.TimeoutEvent) {
	// A timeout carries its sender's highest QC, which is how a lagging replica
	// catches up with no NewView message in the protocol.
	c.updateHighQC(e.HighQC)
	if e.View < c.view {
		return
	}
	sigs := c.timeouts[e.View]
	if slices.ContainsFunc(sigs, func(s hotstuff.Signature) bool { return s.Signer == e.Sig.Signer }) {
		return
	}
	sigs = append(sigs, e.Sig)
	c.timeouts[e.View] = sigs
	if len(sigs) < c.quorum {
		return
	}
	tc := hotstuff.TimeoutCert{View: e.View, Sigs: canonical(sigs)}
	c.advanceView(hotstuff.SyncInfo{QC: c.highQC, TC: &tc})
}

func (c *Core) onViewTimeout(e hotstuff.ViewTimeoutEvent) {
	if e.View != c.view {
		return
	}
	c.dur.ViewTimedOut()
	sig, err := c.crypto.Sign(hotstuff.TimeoutDigest(c.view))
	if err != nil {
		return
	}
	c.net.Timeout(hotstuff.TimeoutMsg{View: c.view, Sig: sig, HighQC: c.highQC})
	c.resetTimer() // keep timing out until a QC or a TC moves the view
}

func (c *Core) onFetched(e hotstuff.FetchedEvent) {
	c.store.Put(e.Block)
	delete(c.fetching, e.Block.Hash())
	if c.pending != nil {
		c.commit(c.pending)
	}
}

// commit runs the commit rule for b and executes as far as it can. A missing
// ancestor parks b until the fetch answers, which is the only continuation in
// the protocol and is off the critical path: voting needs no ancestors.
func (c *Core) commit(b *hotstuff.Block) {
	target, missing := c.rules.CommitRule(c.State(), b)
	if missing != (hotstuff.Hash{}) {
		c.pending = b
		c.fetch(missing)
		return
	}
	if target == nil || target.View() <= c.committedView {
		c.pending = nil
		return
	}
	if c.execute(target) {
		c.pending = nil
	} else {
		c.pending = b
	}
}

// execute walks back from target to the last committed block, then executes
// forward so the Executor sees commit order. It reports false if an ancestor is
// missing, having asked for it.
func (c *Core) execute(target *hotstuff.Block) bool {
	var chain []*hotstuff.Block
	for b := target; b.View() > c.committedView && b.Hash() != c.committedHash; {
		chain = append(chain, b)
		parent, ok := c.store.Get(b.Parent())
		if !ok {
			c.fetch(b.Parent())
			return false
		}
		b = parent
	}
	for i := len(chain) - 1; i >= 0; i-- {
		c.exec.Exec(chain[i])
	}
	c.committedView, c.committedHash = target.View(), target.Hash()
	// Prune reports the forks this commit abandoned; step 11 counts them.
	c.store.Prune(target.Hash())
	return true
}

func (c *Core) fetch(h hotstuff.Hash) {
	// At most one in-flight fetch per hash, until the view has moved far
	// enough that no answer is coming.
	if at, ok := c.fetching[h]; ok && c.view < at+fetchRetryViews {
		return
	}
	c.fetching[h] = c.view
	c.net.Fetch(h)
}

func (c *Core) propose(tc *hotstuff.TimeoutCert) {
	// Commands are pulled, not pushed, so a command flood cannot starve
	// protocol messages and no priority logic is needed. A view still gets a
	// block when the queue is empty: the pipeline is what commits earlier
	// blocks.
	cmds, _ := c.cmds.Poll()
	p, ok := c.rules.ProposeRule(c.State(), cmds, tc)
	if !ok {
		return
	}
	sig, err := c.crypto.Sign(p.Block.Hash())
	if err != nil {
		return
	}
	p.Sig = sig
	// Store before sending, so a QC can never arrive for a block we lack. The
	// proposal comes back through the transport's local node, and that is where
	// the leader votes for its own block.
	c.store.Put(p.Block)
	c.net.Propose(p)
}

// canonical copies sigs into the strictly increasing signer order every
// certificate must be in, so a certificate has one wire form.
func canonical(sigs []hotstuff.Signature) []hotstuff.Signature {
	out := slices.Clone(sigs)
	slices.SortFunc(out, func(a, b hotstuff.Signature) int { return cmp.Compare(a.Signer, b.Signer) })
	return out
}

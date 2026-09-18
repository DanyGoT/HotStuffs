package diem

// Pacemaker is the paper's Pacemaker module (3.5): it advances rounds and
// keeps liveness. On the happy path it advances on the certificates carried by
// proposals; on the recovery path it observes a round making no progress and
// advances on a timeout certificate instead.
type Pacemaker struct {
	quorum int
	faulty int

	clock  Clock
	dur    RoundDuration
	sink   EventSink
	net    Transport
	safety *Safety
	tree   *BlockTree

	currentRound    Round
	lastRoundTC     *TC
	pendingTimeouts map[Round]*timeoutBucket
	timer           Timer
}

// timeoutBucket accumulates the timeouts reported for one round, deduplicated
// by sender: the paper's set union is over senders, not over signatures.
type timeoutBucket struct {
	infos   []TimeoutInfo
	senders map[ID]struct{}
}

// NewPacemaker returns a pacemaker at round 0 with no timer armed. Start on
// Core does the first advance.
func NewPacemaker(quorum, faulty int, clock Clock, dur RoundDuration, sink EventSink, net Transport, safety *Safety, tree *BlockTree) *Pacemaker {
	return &Pacemaker{
		quorum:          quorum,
		faulty:          faulty,
		clock:           clock,
		dur:             dur,
		sink:            sink,
		net:             net,
		safety:          safety,
		tree:            tree,
		pendingTimeouts: map[Round]*timeoutBucket{},
	}
}

// CurrentRound is the round this replica is in.
func (p *Pacemaker) CurrentRound() Round { return p.currentRound }

// LastRoundTC is the certificate that justified entry to the current round, or
// nil when a QC justified it.
func (p *Pacemaker) LastRoundTC() *TC { return p.lastRoundTC }

// Stop disarms the round timer.
func (p *Pacemaker) Stop() {
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

// startTimer enters newRound and arms its timer. The paper leaves the duration
// formula open — "4*delta, or alpha + beta*commit_gap(r) if delta is unknown" —
// so it is a seam here, and the default is the exponential backoff both
// protocols in this repository share.
func (p *Pacemaker) startTimer(newRound Round) {
	p.Stop()
	p.currentRound = newRound
	for r := range p.pendingTimeouts {
		if r < newRound {
			delete(p.pendingTimeouts, r) // only the current round can still form a TC
		}
	}
	p.dur.ViewStarted()
	// The callback runs off the consensus goroutine, so it may only enqueue.
	p.timer = p.clock.AfterFunc(p.dur.Duration(), func() {
		p.sink.Push(LocalTimeoutEvent{Round: newRound})
	})
}

// LocalTimeoutRound broadcasts this replica's timeout for the current round.
//
// The paper's save_consensus_state() has no counterpart here: the two counters
// it would persist live in Safety, and this prototype keeps no durable state.
func (p *Pacemaker) LocalTimeoutRound() {
	p.dur.ViewTimedOut()
	info := p.safety.MakeTimeout(p.currentRound, p.tree.HighQC(), p.lastRoundTC)
	if info == nil {
		return
	}
	p.net.Timeout(&TimeoutMsg{
		TmoInfo:      *info,
		LastRoundTC:  p.lastRoundTC,
		HighCommitQC: p.tree.HighCommitQC(),
	})
	// Re-arm. The paper stops the timer here and relies on a TC arriving; a
	// replica whose broadcast is lost would then sit with no timer at all, so
	// the timeout is retransmitted until a QC or a TC moves the round.
	p.startTimer(p.currentRound)
}

// ProcessRemoteTimeout accumulates tmo and returns the certificate it
// completed, or nil.
//
// f+1 timeouts mean at least one honest replica gave up, so this replica gives
// up too rather than waiting out its own timer — Bracha-style amplification,
// and what makes every honest replica form the TC within two message delays of
// the first.
func (p *Pacemaker) ProcessRemoteTimeout(tmo *TimeoutMsg) *TC {
	info := tmo.TmoInfo
	if info.Round < p.currentRound {
		return nil
	}
	b := p.pendingTimeouts[info.Round]
	if b == nil {
		b = &timeoutBucket{senders: map[ID]struct{}{}}
		p.pendingTimeouts[info.Round] = b
	}
	if _, seen := b.senders[info.Sender]; seen {
		// The paper leaves its two count tests outside this guard. With a set
		// of senders a re-add does not change the size, so re-running them
		// fires the f+1 branch a second time and re-emits a TC for a round
		// already left behind. Timeouts are retransmitted here, so duplicates
		// are certain rather than merely possible.
		return nil
	}
	b.senders[info.Sender] = struct{}{}
	b.infos = append(b.infos, info)

	switch len(b.senders) {
	case p.faulty + 1:
		p.Stop()
		p.LocalTimeoutRound()
	case p.quorum:
		votes := make([]TimeoutVote, 0, len(b.infos))
		for _, i := range b.infos {
			votes = append(votes, TimeoutVote{HighQCRound: i.HighQC.Round(), Sig: i.Sig})
		}
		return &TC{Round: info.Round, Votes: votes}
	}
	return nil
}

// AdvanceRoundTC enters the round after tc's. It reports whether the round
// moved, which is what tells Core a new-round event is due.
func (p *Pacemaker) AdvanceRoundTC(tc *TC) bool {
	if tc == nil || tc.Round < p.currentRound {
		return false
	}
	p.lastRoundTC = tc
	p.startTimer(tc.Round + 1)
	return true
}

// AdvanceRoundQC enters the round after qc's. The TC is cleared: entry is
// justified by the certificate alone, and a stale TC carried into a proposal
// would make it ill-formed.
func (p *Pacemaker) AdvanceRoundQC(qc *QC) bool {
	if qc.Round() < p.currentRound {
		return false
	}
	p.dur.ViewSucceeded()
	p.lastRoundTC = nil
	p.startTimer(qc.Round() + 1)
	return true
}

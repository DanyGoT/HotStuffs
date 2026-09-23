package diem

import (
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// sim is a deterministic N-replica harness: one shared fake clock, one FIFO
// delivery queue, every replica stepping on the test goroutine. Message order
// is fixed, so a failure reproduces exactly.
type sim struct {
	t     *testing.T
	clock *fake.Clock
	ids   []ID

	cores   map[ID]*Core
	vers    map[ID]*Verifier
	pools   map[ID]*FIFOPool
	commits map[ID][]*Block
	down    map[ID]bool

	queue    []func()
	rejected int
}

const (
	simRoundBase = 100 * time.Millisecond
	simRoundMax  = 10 * time.Second
	// simKick is what the clock advances by when the queue runs dry, generous
	// enough to fire a timer however far its backoff has grown.
	simKick = 64 * simRoundBase
)

func newSim(t *testing.T, n int, down ...ID) *sim {
	t.Helper()
	s := &sim{
		t:       t,
		clock:   fake.NewClock(time.Unix(0, 0)),
		cores:   map[ID]*Core{},
		vers:    map[ID]*Verifier{},
		pools:   map[ID]*FIFOPool{},
		commits: map[ID][]*Block{},
		down:    map[ID]bool{},
	}
	for _, id := range down {
		s.down[id] = true
	}
	for i := 1; i <= n; i++ {
		s.ids = append(s.ids, ID(i))
	}
	for _, id := range s.ids {
		ledger := NewMemLedger()
		ledger.OnCommit = func(b *Block) { s.commits[id] = append(s.commits[id], b) }
		pool := NewFIFOPool(1024, 2)
		s.pools[id] = pool
		s.vers[id] = NewVerifier(nocrypto.New(id, n), hotstuff.QuorumSize(n))
		s.cores[id] = New(Config{
			ID:           id,
			Validators:   s.ids,
			Ledger:       ledger,
			Transactions: pool.GetTransactions,
			Crypto:       nocrypto.New(id, n),
			Transport:    &simNet{s: s},
			Clock:        s.clock,
			Duration:     hotstuff.NewDuration(simRoundBase, simRoundMax, 2),
			Sink:         func(e Event) { s.deliver(id, e) },
		})
	}
	return s
}

// deliver queues a step on one replica, but only for a message that passes that
// replica's edge verification: the harness stands in for the network handler
// goroutine, which is where authentication happens. A replica that is down
// receives nothing, which is how a crash fault is modelled.
func (s *sim) deliver(to ID, e Event) {
	if s.down[to] {
		return
	}
	if !s.verify(to, e) {
		s.rejected++
		return
	}
	s.queue = append(s.queue, func() { s.cores[to].Step(e) })
}

func (s *sim) verify(to ID, e Event) bool {
	v := s.vers[to]
	switch e := e.(type) {
	case ProposalEvent:
		return v.VerifyProposal(e.Msg)
	case VoteEvent:
		return v.VerifyVote(e.Msg)
	case TimeoutEvent:
		return v.VerifyTimeout(e.Msg)
	}
	return true // LocalTimeoutEvent is this replica's own timer, not a message
}

// checkNoRejections is the point of counting. Every replica here is honest and
// no message is corrupted in flight, so anything the edge rejects is something
// an honest replica built and its peers would discard.
func (s *sim) checkNoRejections() {
	s.t.Helper()
	if s.rejected != 0 {
		s.t.Fatalf("edge verification rejected %d honest messages", s.rejected)
	}
}

func (s *sim) broadcast(e Event) {
	for _, id := range s.ids {
		s.deliver(id, e)
	}
}

// run starts every live replica and processes at most steps deliveries,
// advancing the clock whenever the queue runs dry.
func (s *sim) run(steps int) {
	s.t.Helper()
	defer s.checkNoRejections()
	for _, id := range s.ids {
		if !s.down[id] {
			s.cores[id].Start()
		}
	}
	for range steps {
		if len(s.queue) == 0 {
			s.clock.Advance(simKick)
			if len(s.queue) == 0 {
				return
			}
		}
		f := s.queue[0]
		s.queue = s.queue[1:]
		f()
	}
}

type simNet struct{ s *sim }

func (n *simNet) Proposal(p *ProposalMsg) { n.s.broadcast(ProposalEvent{Msg: p}) }
func (n *simNet) Vote(v *VoteMsg, to ID)  { n.s.deliver(to, VoteEvent{Msg: v}) }
func (n *simNet) Timeout(m *TimeoutMsg)   { n.s.broadcast(TimeoutEvent{Msg: m}) }

// live is the replicas that were not crashed.
func (s *sim) live() []ID {
	var out []ID
	for _, id := range s.ids {
		if !s.down[id] {
			out = append(out, id)
		}
	}
	return out
}

// checkAgreement is the safety property: no two replicas commit different
// blocks at the same height, so the shorter commit log is always a prefix of
// the longer.
func (s *sim) checkAgreement() {
	s.t.Helper()
	for _, a := range s.live() {
		for _, b := range s.live() {
			if a >= b {
				continue
			}
			x, y := s.commits[a], s.commits[b]
			for i := range min(len(x), len(y)) {
				if x[i].ID() != y[i].ID() {
					s.t.Fatalf("replicas %d and %d disagree at commit %d: round %d vs round %d",
						a, b, i, x[i].Round, y[i].Round)
				}
			}
		}
	}
}

// checkChained is the structural property: committed blocks form one chain,
// each the parent of the next, with strictly increasing rounds.
func (s *sim) checkChained() {
	s.t.Helper()
	for _, id := range s.live() {
		c := s.commits[id]
		for i := 1; i < len(c); i++ {
			if c[i].ParentID() != c[i-1].ID() {
				s.t.Fatalf("replica %d: commit %d (round %d) does not extend commit %d (round %d)",
					id, i, c[i].Round, i-1, c[i-1].Round)
			}
			if c[i].Round <= c[i-1].Round {
				s.t.Fatalf("replica %d: commit rounds not increasing: %d then %d", id, c[i-1].Round, c[i].Round)
			}
		}
	}
}

func (s *sim) checkProgress(want int) {
	s.t.Helper()
	for _, id := range s.live() {
		if n := len(s.commits[id]); n < want {
			s.t.Fatalf("replica %d committed %d blocks, want at least %d", id, n, want)
		}
	}
}

func TestHappyPathCommits(t *testing.T) {
	s := newSim(t, 4)
	for i := range 40 {
		s.pools[1].Add([]byte{byte(i)})
	}
	s.run(4000)

	s.checkProgress(8)
	s.checkAgreement()
	s.checkChained()
}

// TestCrashedLeaderRecovers exercises the timeout path: replica 1 leads round
// 1 and never proposes, so the round can only advance on a TC.
func TestCrashedLeaderRecovers(t *testing.T) {
	s := newSim(t, 4, 1)
	s.run(4000)

	s.checkProgress(5)
	s.checkAgreement()
	s.checkChained()
	for _, id := range s.live() {
		if r := s.commits[id][0].Round; r == 1 {
			t.Fatalf("replica %d committed round 1, but its leader was crashed", id)
		}
	}
}

// TestCommitsAreTwoChains is the commit rule itself: DiemBFT commits a block
// only as the head of a contiguous 2-chain, so every committed block has a
// certified child in the very next round.
func TestCommitsAreTwoChains(t *testing.T) {
	s := newSim(t, 4)
	s.run(4000)
	s.checkProgress(8)

	for _, id := range s.live() {
		for _, b := range s.commits[id] {
			if b.Round == 0 {
				continue
			}
			if b.QC.Round()+1 != b.Round {
				t.Fatalf("replica %d committed block at round %d over a QC for round %d: not a 2-chain",
					id, b.Round, b.QC.Round())
			}
		}
	}
}

// TestPayloadIsCommitted checks the ledger actually carries transactions
// through, not just empty blocks.
func TestPayloadIsCommitted(t *testing.T) {
	s := newSim(t, 4)
	for i := range 40 {
		for _, id := range s.ids {
			s.pools[id].Add([]byte{byte(i)})
		}
	}
	s.run(4000)
	s.checkProgress(8)

	var payloads int
	for _, b := range s.commits[1] {
		payloads += len(b.Payload)
	}
	if payloads == 0 {
		t.Fatal("no transactions committed")
	}
}

// dupNet counts what a replica sent.
type dupNet struct{ proposals, votes, timeouts int }

func (n *dupNet) Proposal(*ProposalMsg) { n.proposals++ }
func (n *dupNet) Vote(*VoteMsg, ID)     { n.votes++ }
func (n *dupNet) Timeout(*TimeoutMsg)   { n.timeouts++ }

// TestDuplicateTimeoutDoesNotRetrigger pins the one place this implementation
// departs from process_remote_timeout: the paper's f+1 and 2f+1 tests sit
// outside the duplicate-sender guard, so a resent timeout runs them again on an
// unchanged sender set. Timeouts are retransmitted while a round is stuck, so
// the duplicate is certain, and re-firing means a second Bracha broadcast and a
// second TC for a round already abandoned.
func TestDuplicateTimeoutDoesNotRetrigger(t *testing.T) {
	const n = 4
	quorum, faulty := hotstuff.QuorumSize(n), hotstuff.Faulty(n)

	ledger := NewMemLedger()
	signer := nocrypto.New(1, n)
	tree := NewBlockTree(1, quorum, ledger, signer)
	safety := NewSafety(1, NewVerifier(signer, quorum), signer, ledger, tree)
	net := &dupNet{}
	pm := NewPacemaker(quorum, faulty, fake.NewClock(time.Unix(0, 0)),
		hotstuff.NewDuration(simRoundBase, simRoundMax, 2), func(Event) {}, net, safety, tree)
	pm.AdvanceRoundQC(genesisQC) // round 1

	timeout := func(from ID) *TimeoutMsg {
		t.Helper()
		s := NewSafety(from, NewVerifier(nocrypto.New(from, n), quorum), nocrypto.New(from, n), NewMemLedger(), tree)
		info := s.MakeTimeout(1, genesisQC, nil)
		if info == nil {
			t.Fatalf("replica %d refused to time out round 1", from)
		}
		return &TimeoutMsg{TmoInfo: *info, HighCommitQC: genesisQC}
	}

	pm.ProcessRemoteTimeout(timeout(2))
	pm.ProcessRemoteTimeout(timeout(2)) // duplicate, still one sender
	if net.timeouts != 0 {
		t.Fatalf("broadcast after %d distinct senders, want none below f+1 = %d", 1, faulty+1)
	}

	pm.ProcessRemoteTimeout(timeout(3)) // f+1 distinct senders: Bracha timeout
	if net.timeouts != 1 {
		t.Fatalf("f+1 senders produced %d broadcasts, want 1", net.timeouts)
	}
	pm.ProcessRemoteTimeout(timeout(3)) // duplicate, must not fire again
	if net.timeouts != 1 {
		t.Fatalf("a duplicate timeout produced %d broadcasts, want 1", net.timeouts)
	}

	if tc := pm.ProcessRemoteTimeout(timeout(4)); tc == nil {
		t.Fatalf("quorum of %d senders produced no TC", quorum)
	}
	if tc := pm.ProcessRemoteTimeout(timeout(4)); tc != nil {
		t.Fatal("a duplicate timeout produced a second TC for the same round")
	}
}

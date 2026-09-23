package diemnet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const recvTimeout = 5 * time.Second

// insecureDial is the loopback dial option every test cluster uses; there is
// no TLS story here, only the transport.
var insecureDial = gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))

// recv reads one event off q, failing the test after a generous timeout rather
// than blocking forever on a bug.
func recv(t *testing.T, q diem.Queue) diem.Event {
	t.Helper()
	select {
	case e := <-q:
		return e
	case <-time.After(recvTimeout):
		t.Fatal("timed out waiting for an event")
		return nil
	}
}

// drained reports whether q is empty right now.
func drained(q diem.Queue) bool {
	select {
	case <-q:
		return false
	default:
		return true
	}
}

type peer struct {
	tr *Transport
	q  diem.Queue
}

// newGroup builds n Gorums-local replicas wired into one peer group and starts
// them, registering cleanup to stop everything in the right order.
// GORUMS: peer addresses must all be known before any server is constructed,
// so this binds n real loopback listeners via NewLocalServers rather than
// letting each transport pick its own port.
func newGroup(t *testing.T, n int) []*peer {
	t.Helper()
	srvs, stop, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(insecureDial))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	peers := make([]*peer, n)
	for i := range n {
		id := diem.ID(i + 1)
		q := diem.NewQueue(256)
		peers[i] = &peer{
			tr: New(Config{
				ID: id, Server: srvs[i], Sink: q.Push,
				Verifier: diem.NewVerifier(nocrypto.New(id, n), hotstuff.QuorumSize(n)),
			}),
			q: q,
		}
	}
	for _, p := range peers {
		p.tr.Start()
	}
	t.Cleanup(func() {
		for _, p := range peers {
			p.tr.Stop()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i, p := range peers {
		if err := p.tr.WaitForPeers(ctx); err != nil {
			t.Fatalf("replica %d WaitForPeers: %v", i+1, err)
		}
	}
	return peers
}

// round1 builds the three message types for round 1 over the genesis
// certificate, signed by the nocrypto signer for from in a group of n.
func round1(t *testing.T, from diem.ID, n int) (*diem.ProposalMsg, *diem.VoteMsg, *diem.TimeoutMsg) {
	t.Helper()
	signer := nocrypto.New(from, n)
	sign := func(h diem.Hash) diem.Signature {
		t.Helper()
		s, err := signer.Sign(h)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	qc := diem.GenesisQC()
	blk := diem.NewBlock(from, 1, [][]byte{[]byte("x")}, qc)
	proposal := &diem.ProposalMsg{
		Block:        blk,
		HighCommitQC: qc,
		Sender:       from,
		Sig:          sign(blk.ID()),
	}

	voteInfo := diem.VoteInfo{
		ID:          blk.ID(),
		Round:       1,
		ParentID:    qc.VoteInfo.ID,
		ExecStateID: diem.ExecuteHash(diem.Hash{}, blk.Payload),
	}
	commit := diem.LedgerCommitInfo{VoteInfoHash: diem.VoteInfoHash(voteInfo)}
	vote := &diem.VoteMsg{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		HighCommitQC:     qc,
		Sender:           from,
		Sig:              sign(diem.LedgerCommitDigest(commit)),
	}

	timeout := &diem.TimeoutMsg{
		TmoInfo: diem.TimeoutInfo{
			Round:  1,
			HighQC: qc,
			Sender: from,
			Sig:    sign(diem.TimeoutDigest(1, 0)),
		},
		HighCommitQC: qc,
	}
	return proposal, vote, timeout
}

// TestMulticastReachesAll checks that a proposal and a timeout reach all four
// replicas, the sender included.
//
// The sender receiving its own message over the same in-process local node is
// what keeps every replica's inbound path identical regardless of who sent the
// message, so Core needs no "this one is mine" branch.
func TestMulticastReachesAll(t *testing.T) {
	const n = 4
	peers := newGroup(t, n)
	proposal, _, timeout := round1(t, 1, n)

	t.Run("Proposal", func(t *testing.T) {
		peers[0].tr.Proposal(proposal)
		for i, p := range peers {
			e, ok := recv(t, p.q).(diem.ProposalEvent)
			if !ok {
				t.Fatalf("replica %d: got a non-proposal event", i+1)
			}
			if e.Msg.Block.ID() != proposal.Block.ID() {
				t.Errorf("replica %d: block id = %x, want %x", i+1, e.Msg.Block.ID(), proposal.Block.ID())
			}
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		peers[0].tr.Timeout(timeout)
		for i, p := range peers {
			e, ok := recv(t, p.q).(diem.TimeoutEvent)
			if !ok {
				t.Fatalf("replica %d: got a non-timeout event", i+1)
			}
			if e.Msg.TmoInfo.Round != 1 || e.Msg.TmoInfo.Sender != 1 {
				t.Errorf("replica %d: tmo info = %+v, want round 1 from sender 1", i+1, e.Msg.TmoInfo)
			}
		}
	})
}

// TestVoteIsUnicast is the one place this transport differs from the HotStuff
// one: DiemBFT 3.1 sends a vote to the next round's leader alone, so exactly
// one replica must see it and the other three must see nothing.
func TestVoteIsUnicast(t *testing.T) {
	const n, to = 4, diem.ID(3)
	peers := newGroup(t, n)
	_, vote, _ := round1(t, 1, n)

	peers[0].tr.Vote(vote, to)

	e, ok := recv(t, peers[to-1].q).(diem.VoteEvent)
	if !ok {
		t.Fatalf("replica %d: got a non-vote event", to)
	}
	if e.Msg.Sender != vote.Sender || e.Msg.VoteInfo.ID != vote.VoteInfo.ID {
		t.Errorf("vote = %+v, want sender %d on block %x", e.Msg, vote.Sender, vote.VoteInfo.ID)
	}
	// A multicast would already have delivered to the others by now, since the
	// addressee's copy travels the same sender goroutine and the same queue.
	for i, p := range peers {
		if diem.ID(i+1) == to {
			continue
		}
		if !drained(p.q) {
			t.Errorf("replica %d received a vote addressed to replica %d", i+1, to)
		}
	}
}

// TestVoteToUnknownReplicaIsDropped: the peer configuration has no node for
// that ID, so the send is counted rather than panicking on a nil node.
func TestVoteToUnknownReplicaIsDropped(t *testing.T) {
	const n = 4
	peers := newGroup(t, n)
	_, vote, _ := round1(t, 1, n)

	before := peers[0].tr.Counters().OutboundDropped
	peers[0].tr.Vote(vote, diem.ID(n+1))

	if !waitFor(recvTimeout, func() bool { return peers[0].tr.Counters().OutboundDropped > before }) {
		t.Errorf("OutboundDropped = %d, want > %d", peers[0].tr.Counters().OutboundDropped, before)
	}
}

// TestHandlerRejectsMalformed drives the handler directly, with no server
// involved. Each row is converter- or verifier-rejected, and each must
// increment rejected without pushing an event. This is the test that shows the
// transport boundary is the security boundary: stage B moved authentication
// here so the consensus goroutine never runs a signature check.
func TestHandlerRejectsMalformed(t *testing.T) {
	const n = 4
	q := diem.NewQueue(8)
	h := &handler{ver: diem.NewVerifier(nocrypto.New(1, n), hotstuff.QuorumSize(n)), sink: q.Push}
	proposal, vote, timeout := round1(t, 1, n)

	forged := diempb.Signature_builder{Signer: 1, Sig: []byte("forged")}.Build()

	steps := []struct {
		name string
		run  func()
	}{
		{"proposal with no block", func() {
			h.Proposal(gorums.ServerContext{}, diempb.ProposalMsg_builder{Sender: 1, Sig: forged}.Build())
		}},
		{"proposal whose signature does not verify", func() {
			in := toProposal(proposal)
			in.SetSig(forged)
			h.Proposal(gorums.ServerContext{}, in)
		}},
		{"proposal whose sender is not its signer", func() {
			in := toProposal(proposal)
			in.SetSender(2)
			h.Proposal(gorums.ServerContext{}, in)
		}},
		{"vote whose signature does not verify", func() {
			in := toVote(vote)
			in.SetSig(forged)
			h.Vote(gorums.ServerContext{}, in)
		}},
		{"vote whose vote info was swapped behind the hash", func() {
			in := toVote(vote)
			swapped := vote.VoteInfo
			swapped.Round = 99
			in.SetVoteInfo(toVoteInfo(swapped))
			h.Vote(gorums.ServerContext{}, in)
		}},
		{"timeout with no tmo info", func() {
			h.Timeout(gorums.ServerContext{}, diempb.TimeoutMsg_builder{}.Build())
		}},
		{"timeout whose signature does not verify", func() {
			in := toTimeout(timeout)
			in.GetTmoInfo().SetSig(forged)
			h.Timeout(gorums.ServerContext{}, in)
		}},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			before := h.rejected.Load()
			step.run()
			if got := h.rejected.Load(); got != before+1 {
				t.Errorf("rejected = %d, want %d", got, before+1)
			}
			if !drained(q) {
				t.Error("queue is not empty, want nothing pushed")
			}
		})
	}
}

// TestHandlerAcceptsWellFormed is the other half of the boundary: the same
// three messages, unmodified, must reach the sink.
func TestHandlerAcceptsWellFormed(t *testing.T) {
	const n = 4
	q := diem.NewQueue(8)
	h := &handler{ver: diem.NewVerifier(nocrypto.New(1, n), hotstuff.QuorumSize(n)), sink: q.Push}
	proposal, vote, timeout := round1(t, 1, n)

	h.Proposal(gorums.ServerContext{}, toProposal(proposal))
	h.Vote(gorums.ServerContext{}, toVote(vote))
	h.Timeout(gorums.ServerContext{}, toTimeout(timeout))

	if got := h.rejected.Load(); got != 0 {
		t.Fatalf("rejected = %d, want 0", got)
	}
	for _, want := range []string{"proposal", "vote", "timeout"} {
		switch e := recv(t, q).(type) {
		case diem.ProposalEvent:
			if want != "proposal" {
				t.Errorf("got a proposal, want a %s", want)
			}
			if e.Msg.Block.ID() != proposal.Block.ID() {
				t.Errorf("block id = %x, want %x", e.Msg.Block.ID(), proposal.Block.ID())
			}
		case diem.VoteEvent:
			if want != "vote" {
				t.Errorf("got a vote, want a %s", want)
			}
		case diem.TimeoutEvent:
			if want != "timeout" {
				t.Errorf("got a timeout, want a %s", want)
			}
		}
	}
}

// TestOutboundQueueDrops never calls Start, so nothing drains the outbound
// queue; sends must drop rather than block. Outbound drops are safe because
// loss is what the round timer recovers from, while the inbound queue is
// bounded and blocking for the opposite reason: an already-accepted event must
// never be lost.
func TestOutboundQueueDrops(t *testing.T) {
	const n = 1
	tr := New(Config{
		ID: 1, Listen: "127.0.0.1:0", OutQueue: 1,
		// This replica's own ID resolves to an in-process node regardless of
		// the address given, so the placeholder is never dialed.
		Peers:    map[uint32]string{1: "127.0.0.1:0"},
		Sink:     diem.NewQueue(8).Push,
		Verifier: diem.NewVerifier(nocrypto.New(1, n), hotstuff.QuorumSize(n)),
	})
	t.Cleanup(tr.Stop)
	proposal, _, _ := round1(t, 1, n)

	done := make(chan struct{})
	go func() {
		for range 5 {
			tr.Proposal(proposal)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(recvTimeout):
		t.Fatal("Proposal blocked instead of dropping")
	}

	if got := tr.Counters().OutboundDropped; got == 0 {
		t.Errorf("OutboundDropped = %d, want > 0", got)
	}
}

// TestStopIdempotent checks Stop is safe to call twice, whether or not Start
// was ever called.
func TestStopIdempotent(t *testing.T) {
	newTransport := func() *Transport {
		return New(Config{
			ID: 1, Listen: "127.0.0.1:0",
			Peers:    map[uint32]string{1: "127.0.0.1:0"},
			Sink:     diem.NewQueue(1).Push,
			Verifier: diem.NewVerifier(nocrypto.New(1, 1), hotstuff.QuorumSize(1)),
		})
	}

	t.Run("never started", func(t *testing.T) {
		tr := newTransport()
		tr.Stop()
		tr.Stop()
	})

	t.Run("started", func(t *testing.T) {
		tr := newTransport()
		tr.Start()
		tr.Stop()
		tr.Stop()
	})
}

// --- the end-to-end run ---

const (
	testRoundBase = 20 * time.Millisecond
	testRoundMax  = 2 * time.Second
)

// node is one replica's full stack over the Gorums transport, plus the commit
// log the test reads.
type node struct {
	id   diem.ID
	tr   *Transport
	q    diem.Queue
	core *diem.Core
	loop *diem.Loop

	mu      sync.Mutex
	commits []*diem.Block
}

// log snapshots the commit log. MemLedger.OnCommit runs on the consensus
// goroutine and the test reads from its own, which is the whole reason for the
// mutex — it guards application state, never protocol state.
func (n *node) log() []*diem.Block {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*diem.Block(nil), n.commits...)
}

// newCluster builds n replicas on one process's Gorums local servers, each with
// a real ECDSA key. The wiring order is forced by the constructors: the queue
// is the only dependency-free piece, so the transport and the core both hang
// off it.
func newCluster(t *testing.T, n int) []*node {
	t.Helper()
	srvs, stopSrvs, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(insecureDial))
	if err != nil {
		t.Fatalf("NewLocalServers: %v", err)
	}
	t.Cleanup(stopSrvs)

	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	validators := make([]diem.ID, n)
	for i := range n {
		validators[i] = diem.ID(i + 1)
	}

	nodes := make([]*node, n)
	for i := range n {
		id := diem.ID(i + 1)
		nd := &node{id: id}
		signer := crypto.New(id, privs[id], pubs)
		ledger := diem.NewMemLedger()
		ledger.OnCommit = func(b *diem.Block) {
			nd.mu.Lock()
			nd.commits = append(nd.commits, b)
			nd.mu.Unlock()
		}
		nd.q = diem.NewQueue(1024)
		nd.tr = New(Config{
			ID: id, Server: srvs[i], Sink: nd.q.Push,
			Verifier: diem.NewVerifier(signer, hotstuff.QuorumSize(n)),
		})
		nd.core = diem.New(diem.Config{
			ID:         id,
			Validators: validators,
			Ledger:     ledger,
			Crypto:     signer,
			Transport:  nd.tr,
			Clock:      hotstuff.SystemClock{},
			Duration:   hotstuff.NewDuration(testRoundBase, testRoundMax, 2),
			Sink:       nd.q.Push,
		})
		nd.loop = diem.NewLoop(nd.core, nd.q)
		nodes[i] = nd
	}
	return nodes
}

// run starts every node and returns the func that stops them all. Stopping is
// the dance replica.Diem also has to do: cancel the loops, then keep the
// inbound queues moving while the transports go down, because those queues are
// bounded and blocking and Gorums never waits for its handler goroutines. It is
// idempotent, so a test can both defer it and call it early to quiesce the
// cluster before reading state that belongs to the loop goroutine.
func run(t *testing.T, nodes []*node) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var loops sync.WaitGroup
	for _, nd := range nodes {
		nd.tr.Start()
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	for _, nd := range nodes {
		if err := nd.tr.WaitForPeers(waitCtx); err != nil {
			t.Fatalf("replica %d WaitForPeers: %v", nd.id, err)
		}
	}
	for _, nd := range nodes {
		nd.core.Start()
		loops.Go(func() { _ = nd.loop.Run(ctx) })
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			drained := make(chan struct{})
			var drainers sync.WaitGroup
			for _, nd := range nodes {
				drainers.Go(func() {
					for {
						select {
						case <-drained:
							return
						case <-nd.q:
						}
					}
				})
			}
			for _, nd := range nodes {
				nd.tr.Stop()
			}
			close(drained)
			drainers.Wait()
			loops.Wait()
		})
	}
}

// waitFor polls pred until it holds or timeout passes, so no test needs a sleep
// to synchronise on a condition.
func waitFor(timeout time.Duration, pred func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if pred() {
			return true
		}
		if time.Now().After(deadline) {
			return pred()
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func depths(nodes []*node) []int {
	d := make([]int, len(nodes))
	for i, nd := range nodes {
		d[i] = len(nd.log())
	}
	return d
}

// TestClusterCommitsOverGorums is the box this whole package exists for: four
// DiemBFT replicas, real ECDSA, real Gorums over loopback, committing an
// agreeing chain. Everything before it tests one message at a time.
func TestClusterCommitsOverGorums(t *testing.T) {
	const n, wantDepth = 4, 10
	nodes := newCluster(t, n)
	stop := run(t, nodes)
	t.Cleanup(stop)

	if !waitFor(20*time.Second, func() bool {
		for _, nd := range nodes {
			if len(nd.log()) < wantDepth {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("commit depths %v, want every replica >= %d", depths(nodes), wantDepth)
	}

	// Quiesce before reading anything: a Core's state belongs to its loop
	// goroutine and is not safe to read from here while the loop is running.
	stop()

	logs := make([][]*diem.Block, n)
	for i, nd := range nodes {
		logs[i] = nd.log()
	}
	for i := range logs {
		for j := i + 1; j < n; j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if logs[i][k].ID() != logs[j][k].ID() {
					t.Fatalf("replicas %d and %d disagree at commit %d: round %d against round %d",
						i+1, j+1, k, logs[i][k].Round, logs[j][k].Round)
				}
			}
		}
	}
	// Every block id here was recomputed by the receiver from the wire form.
	// A chain this deep that still agrees is the round-trip assertion at scale.
	for i, log := range logs {
		for k := 1; k < len(log); k++ {
			if log[k].ParentID() != log[k-1].ID() {
				t.Fatalf("replica %d: commit %d does not extend commit %d", i+1, k, k-1)
			}
		}
	}

	// Every replica here is honest and nothing is corrupted in flight, so
	// anything rejected is a message an honest replica built and its peers
	// would discard.
	for i, nd := range nodes {
		if c := nd.tr.Counters(); c.Rejected != 0 || c.OutboundDropped != 0 {
			t.Errorf("replica %d: Counters = %+v, want zero", i+1, c)
		}
	}
	for i, nd := range nodes {
		if got := nd.core.State().DeclinedMissingAncestor; got != 0 {
			t.Logf("replica %d declined %d votes for a missing ancestor: DiemBFT 3 has no block-sync, so this is the standing cost", i+1, got)
		}
	}
}

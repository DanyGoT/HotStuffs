package diemnet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const recvTimeout = 5 * time.Second

// insecureDial is the loopback dial option every test cluster uses; there is
// no TLS story here, only the transport.
var insecureDial = gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))

// testKeys caches one key set per group size, so every signer a test builds for
// a group of n verifies the others' signatures.
var testKeys = map[int]struct {
	privs map[uint32]*ecdsa.PrivateKey
	pubs  map[uint32]*ecdsa.PublicKey
}{}

// signer is replica id's signer in a group of n.
func signer(t *testing.T, id uint32, n int) *crypto.Signer {
	t.Helper()
	ks, ok := testKeys[n]
	if !ok {
		privs, pubs, err := crypto.GenerateKeys(n)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		ks.privs, ks.pubs = privs, pubs
		testKeys[n] = ks
	}
	return crypto.New(ks.privs[id], ks.pubs)
}

// recv reads one input off q, failing the test after a generous timeout rather
// than blocking forever on a bug.
func recv(t *testing.T, q chan any) any {
	t.Helper()
	select {
	case e := <-q:
		return e
	case <-time.After(recvTimeout):
		t.Fatal("timed out waiting for an input")
		return nil
	}
}

// sink pushes onto q, blocking when it is full.
func sink(q chan any) func(any) { return func(m any) { q <- m } }

// drained reports whether q is empty right now.
func drained(q chan any) bool {
	select {
	case <-q:
		return false
	default:
		return true
	}
}

type peer struct {
	tr *Transport
	q  chan any
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
		id := uint32(i + 1)
		q := make(chan any, 256)
		peers[i] = &peer{
			tr: New(Config{
				ID: id, Server: srvs[i], Sink: sink(q),
				Verifier: diem.NewVerifier(signer(t, id, n), diem.QuorumSize(n)),
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

// sig signs digest as signer and wraps the result as a proto Signature.
func sig(t *testing.T, signer *crypto.Signer, id uint32, digest []byte) *diempb.Signature {
	t.Helper()
	raw, err := signer.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}
	return diempb.Signature_builder{Signer: id, Sig: raw}.Build()
}

// round1 builds the three message types for round 1 over the genesis
// certificate, signed by from in a group of n.
func round1(t *testing.T, from uint32, n int) (*diempb.ProposalMsg, *diempb.VoteMsg, *diempb.TimeoutMsg) {
	t.Helper()
	signer := signer(t, from, n)

	qc := diem.GenesisQC()
	blk := diem.NewBlock(from, 1, [][]byte{[]byte("x")}, qc)
	proposal := diempb.ProposalMsg_builder{
		Block:        blk,
		HighCommitQc: qc,
		Sender:       from,
		Sig:          sig(t, signer, from, blk.GetId()),
	}.Build()

	voteInfo := diempb.VoteInfo_builder{
		Id:          blk.GetId(),
		Round:       1,
		ParentId:    qc.GetVoteInfo().GetId(),
		ExecStateId: diem.ExecuteHash(make([]byte, 32), blk.GetPayload()),
	}.Build()
	commit := diempb.LedgerCommitInfo_builder{
		CommitStateId: make([]byte, 32),
		VoteInfoHash:  diem.VoteInfoHash(voteInfo),
	}.Build()
	vote := diempb.VoteMsg_builder{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		HighCommitQc:     qc,
		Sender:           from,
		Sig:              sig(t, signer, from, diem.LedgerCommitDigest(commit)),
	}.Build()

	timeout := diempb.TimeoutMsg_builder{
		TmoInfo: diempb.TimeoutInfo_builder{
			Round:  1,
			HighQc: qc,
			Sender: from,
			Sig:    sig(t, signer, from, diem.TimeoutDigest(1, 0)),
		}.Build(),
		HighCommitQc: qc,
	}.Build()
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
			m, ok := recv(t, p.q).(*diempb.ProposalMsg)
			if !ok {
				t.Fatalf("replica %d: got a non-proposal input", i+1)
			}
			if !bytes.Equal(m.GetBlock().GetId(), proposal.GetBlock().GetId()) {
				t.Errorf("replica %d: block id = %x, want %x", i+1, m.GetBlock().GetId(), proposal.GetBlock().GetId())
			}
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		peers[0].tr.Timeout(timeout)
		for i, p := range peers {
			m, ok := recv(t, p.q).(*diempb.TimeoutMsg)
			if !ok {
				t.Fatalf("replica %d: got a non-timeout input", i+1)
			}
			if m.GetTmoInfo().GetRound() != 1 || m.GetTmoInfo().GetSender() != 1 {
				t.Errorf("replica %d: tmo info = %+v, want round 1 from sender 1", i+1, m.GetTmoInfo())
			}
		}
	})
}

// TestVoteIsUnicast: DiemBFT 3.1 sends a vote to the next round's leader alone,
// so exactly one replica must see it and the other three must see nothing.
func TestVoteIsUnicast(t *testing.T) {
	const n, to = 4, uint32(3)
	peers := newGroup(t, n)
	_, vote, _ := round1(t, 1, n)

	peers[0].tr.Vote(vote, to)

	m, ok := recv(t, peers[to-1].q).(*diempb.VoteMsg)
	if !ok {
		t.Fatalf("replica %d: got a non-vote input", to)
	}
	if m.GetSender() != vote.GetSender() || !bytes.Equal(m.GetVoteInfo().GetId(), vote.GetVoteInfo().GetId()) {
		t.Errorf("vote = %+v, want sender %d on block %x", m, vote.GetSender(), vote.GetVoteInfo().GetId())
	}
	// A multicast would already have delivered to the others by now, since the
	// addressee's copy travels the same sender goroutine and the same queue.
	for i, p := range peers {
		if uint32(i+1) == to {
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
	peers[0].tr.Vote(vote, uint32(n+1))

	if !waitFor(recvTimeout, func() bool { return peers[0].tr.Counters().OutboundDropped > before }) {
		t.Errorf("OutboundDropped = %d, want > %d", peers[0].tr.Counters().OutboundDropped, before)
	}
}

// TestHandlerRejectsMalformed drives the handler directly, with no server
// involved. Each row is verifier-rejected, and each must
// increment rejected without pushing anything. This is the test that shows the
// transport boundary is the security boundary: stage B moved authentication
// here so no signature check is made under the replica's lock.
func TestHandlerRejectsMalformed(t *testing.T) {
	const n = 4
	q := make(chan any, 8)
	h := &handler{ver: diem.NewVerifier(signer(t, 1, n), diem.QuorumSize(n)), sink: sink(q)}
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
			in := proto.Clone(proposal).(*diempb.ProposalMsg)
			in.SetSig(forged)
			h.Proposal(gorums.ServerContext{}, in)
		}},
		{"proposal whose sender is not its signer", func() {
			in := proto.Clone(proposal).(*diempb.ProposalMsg)
			in.SetSender(2)
			h.Proposal(gorums.ServerContext{}, in)
		}},
		{"vote whose signature does not verify", func() {
			in := proto.Clone(vote).(*diempb.VoteMsg)
			in.SetSig(forged)
			h.Vote(gorums.ServerContext{}, in)
		}},
		{"vote whose vote info was swapped behind the hash", func() {
			in := proto.Clone(vote).(*diempb.VoteMsg)
			in.GetVoteInfo().SetRound(99)
			h.Vote(gorums.ServerContext{}, in)
		}},
		{"timeout with no tmo info", func() {
			h.Timeout(gorums.ServerContext{}, diempb.TimeoutMsg_builder{}.Build())
		}},
		{"timeout whose signature does not verify", func() {
			in := proto.Clone(timeout).(*diempb.TimeoutMsg)
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
	q := make(chan any, 8)
	h := &handler{ver: diem.NewVerifier(signer(t, 1, n), diem.QuorumSize(n)), sink: sink(q)}
	proposal, vote, timeout := round1(t, 1, n)

	h.Proposal(gorums.ServerContext{}, proto.Clone(proposal).(*diempb.ProposalMsg))
	h.Vote(gorums.ServerContext{}, proto.Clone(vote).(*diempb.VoteMsg))
	h.Timeout(gorums.ServerContext{}, proto.Clone(timeout).(*diempb.TimeoutMsg))

	if got := h.rejected.Load(); got != 0 {
		t.Fatalf("rejected = %d, want 0", got)
	}
	for _, want := range []string{"proposal", "vote", "timeout"} {
		switch m := recv(t, q).(type) {
		case *diempb.ProposalMsg:
			if want != "proposal" {
				t.Errorf("got a proposal, want a %s", want)
			}
			if !bytes.Equal(m.GetBlock().GetId(), proposal.GetBlock().GetId()) {
				t.Errorf("block id = %x, want %x", m.GetBlock().GetId(), proposal.GetBlock().GetId())
			}
		case *diempb.VoteMsg:
			if want != "vote" {
				t.Errorf("got a vote, want a %s", want)
			}
		case *diempb.TimeoutMsg:
			if want != "timeout" {
				t.Errorf("got a timeout, want a %s", want)
			}
		}
	}
}

// holding is an unstarted core whose pending tree holds b, if b is not nil, so
// that Block(b's id) answers with b whatever b's content.
func holding(t *testing.T, b *diempb.Block) *diem.Core {
	t.Helper()
	c := diem.New(diem.Config{
		ID:         1,
		Validators: []uint32{1, 2, 3, 4},
		Ledger:     diem.NewMemLedger(),
		Crypto:     signer(t, 1, 4),
		Transport:  nopNet{},
		Clock:      diem.SystemClock{},
		Backoff:    diem.NewBackoff(time.Second, time.Second, 2),
	})
	if b != nil {
		c.OnBlock(b)
	}
	return c
}

type nopNet struct{}

func (nopNet) Proposal(*diempb.ProposalMsg) {}
func (nopNet) Vote(*diempb.VoteMsg, uint32) {}
func (nopNet) Timeout(*diempb.TimeoutMsg)   {}
func (nopNet) RequestBlock([]byte)          {}

// answer runs every block request p receives against a core holding b, and
// keeps whatever else arrives. The func it returns stops it and hands back what
// it kept.
func answer(t *testing.T, p *peer, b *diempb.Block) func() []any {
	core := holding(t, b)
	var kept []any
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		for {
			select {
			case <-done:
				return
			case m := <-p.q:
				if f, ok := m.(func(*diem.Core)); ok {
					f(core)
				} else {
					kept = append(kept, m)
				}
			}
		}
	}()
	return func() []any {
		close(done)
		<-exited
		for {
			select {
			case m := <-p.q:
				kept = append(kept, m)
			default:
				return kept
			}
		}
	}
}

// TestRequestBlockChecksTheID has one peer answer a block request with a
// forgery that claims the requested id. Only a block whose recomputed id is
// the one asked for may reach the core.
func TestRequestBlockChecksTheID(t *testing.T) {
	const n = 4
	proposal, _, _ := round1(t, 1, n)
	want := proposal.GetBlock()
	forged := diempb.Block_builder{
		Author:  want.GetAuthor(),
		Round:   want.GetRound(),
		Payload: [][]byte{[]byte("forged")},
		Qc:      want.GetQc(),
		Id:      want.GetId(),
	}.Build()

	for _, tc := range []struct {
		name string
		held *diempb.Block // what the third peer answers with
	}{
		{"forgery only", nil},
		{"forgery and block", want},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peers := newGroup(t, n)
			for i, b := range []*diempb.Block{forged, nil, tc.held} {
				stop := answer(t, peers[i+1], b)
				t.Cleanup(func() { stop() })
			}
			self := answer(t, peers[0], nil)

			peers[0].tr.fetch(peers[0].tr.peers(), want.GetId())
			got := self()

			if tc.held == nil {
				if len(got) != 0 {
					t.Fatalf("got %d inputs from a fetch no correct peer answered, want none", len(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d inputs, want the one block", len(got))
			}
			b, ok := got[0].(*diempb.Block)
			if !ok || !proto.Equal(b, want) {
				t.Fatalf("got %+v, want the requested block", got[0])
			}
		})
	}
}

// TestOutboundQueueDrops never calls Start, so nothing drains the outbound
// queue; sends must drop rather than block. Outbound drops are safe because
// loss is what the round timer recovers from, while the inbound queue is
// bounded and blocking for the opposite reason: an already-accepted input must
// never be lost.
func TestOutboundQueueDrops(t *testing.T) {
	const n = 1
	tr := New(Config{
		ID: 1, Listen: "127.0.0.1:0", OutQueue: 1,
		// This replica's own ID resolves to an in-process node regardless of
		// the address given, so the placeholder is never dialed.
		Peers:    map[uint32]string{1: "127.0.0.1:0"},
		Sink:     sink(make(chan any, 8)),
		Verifier: diem.NewVerifier(signer(t, 1, n), diem.QuorumSize(n)),
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
			Sink:     sink(make(chan any, 1)),
			Verifier: diem.NewVerifier(signer(t, 1, 1), diem.QuorumSize(1)),
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
// log the test reads. mu serializes every core call, as replica.Replica does,
// and guards the log, which the ledger appends to inside those calls.
type node struct {
	id   uint32
	tr   *Transport
	core *diem.Core

	mu      sync.Mutex
	stopped bool
	commits []*diempb.Block
}

func (n *node) deliver(m any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.stopped {
		n.core.Dispatch(m)
	}
}

func (n *node) log() []*diempb.Block {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*diempb.Block(nil), n.commits...)
}

// newCluster builds n replicas on one process's Gorums local servers, each with
// a real ECDSA key.
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
	validators := make([]uint32, n)
	for i := range n {
		validators[i] = uint32(i + 1)
	}

	nodes := make([]*node, n)
	for i := range n {
		id := uint32(i + 1)
		nd := &node{id: id}
		signer := crypto.New(privs[id], pubs)
		ledger := diem.NewMemLedger()
		ledger.OnCommit = func(b *diempb.Block) { nd.commits = append(nd.commits, b) }
		nd.tr = New(Config{
			ID: id, Server: srvs[i], Sink: nd.deliver,
			Verifier: diem.NewVerifier(signer, diem.QuorumSize(n)),
		})
		nd.core = diem.New(diem.Config{
			ID:         id,
			Validators: validators,
			Ledger:     ledger,
			Crypto:     signer,
			Transport:  nd.tr,
			Clock:      diem.SystemClock{},
			Backoff:    diem.NewBackoff(testRoundBase, testRoundMax, 2),
			Lock:       &nd.mu,
		})
		nodes[i] = nd
	}
	return nodes
}

// run starts every node and returns the func that stops them all. Each node's
// mu is held until its core has started, so an early message waits for it.
// Stopping marks every node stopped under its mu before the transports go
// down, because Gorums never waits for its handler goroutines. It is
// idempotent, so a test can both defer it and call it early to quiesce the
// cluster before reading core state.
func run(t *testing.T, nodes []*node) func() {
	t.Helper()
	for _, nd := range nodes {
		nd.mu.Lock()
		nd.tr.Start()
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	for _, nd := range nodes {
		if err := nd.tr.WaitForPeers(waitCtx); err != nil {
			for _, nd := range nodes {
				nd.stopped = true
				nd.mu.Unlock()
				nd.tr.Stop()
			}
			t.Fatalf("replica %d WaitForPeers: %v", nd.id, err)
		}
	}
	for _, nd := range nodes {
		nd.core.Start()
		nd.mu.Unlock()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			for _, nd := range nodes {
				nd.mu.Lock()
				nd.stopped = true
				nd.core.Stop()
				nd.mu.Unlock()
			}
			for _, nd := range nodes {
				nd.tr.Stop()
			}
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

	// Quiesce before reading anything, so the logs compared are final.
	stop()

	logs := make([][]*diempb.Block, n)
	for i, nd := range nodes {
		logs[i] = nd.log()
	}
	for i := range logs {
		for j := i + 1; j < n; j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if !bytes.Equal(logs[i][k].GetId(), logs[j][k].GetId()) {
					t.Fatalf("replicas %d and %d disagree at commit %d: round %d against round %d",
						i+1, j+1, k, logs[i][k].GetRound(), logs[j][k].GetRound())
				}
			}
		}
	}
	// Every block id here was recomputed by the receiver from the wire form.
	// A chain this deep that still agrees is the round-trip assertion at scale.
	for i, log := range logs {
		for k := 1; k < len(log); k++ {
			if !bytes.Equal(log[k].GetQc().GetVoteInfo().GetId(), log[k-1].GetId()) {
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
			t.Logf("replica %d declined %d votes for a missing ancestor, lost while it was fetched", i+1, got)
		}
	}
}

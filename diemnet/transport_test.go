package diemnet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/proto/diempb"
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
func signer(t *testing.T, id uint32, n int) *diemcrypto.Signer {
	t.Helper()
	ks, ok := testKeys[n]
	if !ok {
		privs, pubs, err := diemcrypto.GenerateKeys(n)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		ks.privs, ks.pubs = privs, pubs
		testKeys[n] = ks
	}
	return diemcrypto.New(ks.privs[id], ks.pubs)
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

// recorder is an inbound handler that records every message it is handed,
// and answers a block request with held.
type recorder struct {
	q    chan any
	held *diempb.Block
}

func (r *recorder) Proposal(_ gorums.ServerContext, in *diempb.ProposalMsg) { r.q <- in }
func (r *recorder) Vote(_ gorums.ServerContext, in *diempb.VoteMsg)         { r.q <- in }
func (r *recorder) Timeout(_ gorums.ServerContext, in *diempb.TimeoutMsg)   { r.q <- in }

func (r *recorder) RequestBlock(gorums.ServerContext, *diempb.BlockHash) (*diempb.Block, error) {
	if r.held == nil {
		return nil, errNoBlock
	}
	return r.held, nil
}

// record serves p's transport with a recorder in place of a core.
func record(p *peer) { p.tr.serve(&recorder{q: p.q}) }

type peer struct {
	id uint32
	tr *Transport
	q  chan any
}

// newGroup builds n Gorums-local replicas wired into one peer group and starts
// each with start, registering cleanup to stop everything in the right order.
// GORUMS: peer addresses must all be known before any server is constructed,
// so this binds n real loopback listeners via NewLocalServers rather than
// letting each transport pick its own port.
func newGroup(t *testing.T, n int, start func(*peer)) []*peer {
	t.Helper()
	srvs, rejected, stop := localServers(t, n, signer(t, 1, n))
	t.Cleanup(stop)

	peers := make([]*peer, n)
	for i := range n {
		id := uint32(i + 1)
		q := make(chan any, 256)
		peers[i] = &peer{
			id: id,
			tr: New(Config{
				ID: id, Server: srvs[i], Rejected: rejected,
				Verifier: diem.NewVerifier(signer(t, id, n), diem.QuorumSize(n)),
			}),
			q: q,
		}
	}
	for _, p := range peers {
		start(p)
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

// localServers is n Gorums local servers sharing one VerifyInterceptor over
// c's keys, with the counter it rejects into.
func localServers(t *testing.T, n int, c diem.Crypto) ([]*gorums.Server, *atomic.Uint64, func()) {
	t.Helper()
	rejected := new(atomic.Uint64)
	verify := VerifyInterceptor(diem.NewVerifier(c, diem.QuorumSize(n)), rejected)
	srvs, stop, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(insecureDial),
		gorums.WithLocalServerOptions(gorums.WithServerInterceptors(verify)))
	if err != nil {
		t.Fatalf("NewLocalServers: %v", err)
	}
	return srvs, rejected, stop
}

// sig signs digest as signer and wraps the result as a proto Signature.
func sig(t *testing.T, signer *diemcrypto.Signer, id uint32, digest []byte) *diempb.Signature {
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

	timeout := diempb.TimeoutMsg_builder{
		TmoInfo: diempb.TimeoutInfo_builder{
			Round:  1,
			HighQc: qc,
			Sender: from,
			Sig:    sig(t, signer, from, diempb.TimeoutDigest(1, 0)),
		}.Build(),
		HighCommitQc: qc,
	}.Build()
	return proposal, voteOn(t, from, n, blk), timeout
}

// voteOn is from's vote for blk, a round-1 block over the genesis certificate,
// in a group of n.
func voteOn(t *testing.T, from uint32, n int, blk *diempb.Block) *diempb.VoteMsg {
	t.Helper()
	qc := diem.GenesisQC()
	voteInfo := diempb.VoteInfo_builder{
		Id:          blk.GetId(),
		Round:       1,
		ParentId:    qc.BlockID(),
		ExecStateId: diem.ExecuteHash(make([]byte, 32), blk.GetPayload()),
	}.Build()
	commit := diempb.LedgerCommitInfo_builder{
		CommitStateId: make([]byte, 32),
		VoteInfoHash:  voteInfo.Hash(),
	}.Build()
	return diempb.VoteMsg_builder{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		HighCommitQc:     qc,
		Sender:           from,
		Sig:              sig(t, signer(t, from, n), from, commit.Digest()),
	}.Build()
}

// TestMulticastReachesAll checks that a proposal and a timeout reach all four
// replicas, the sender included.
//
// The sender receiving its own message over the same in-process local node is
// what keeps every replica's inbound path identical regardless of who sent the
// message, so Core needs no "this one is mine" branch.
func TestMulticastReachesAll(t *testing.T) {
	const n = 4
	peers := newGroup(t, n, record)
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
	peers := newGroup(t, n, record)
	_, vote, timeout := round1(t, 1, n)

	// The timeout marks the end: Gorums delivers one sender's messages to a
	// replica in order, so a vote sent to a replica arrives before the timeout.
	peers[0].tr.Vote(vote, to)
	peers[0].tr.Timeout(timeout)

	for i, p := range peers {
		m := recv(t, p.q)
		if v, ok := m.(*diempb.VoteMsg); ok {
			if uint32(i+1) != to {
				t.Errorf("replica %d received a vote addressed to replica %d", i+1, to)
			} else if v.GetSender() != vote.GetSender() || !bytes.Equal(v.GetVoteInfo().GetId(), vote.GetVoteInfo().GetId()) {
				t.Errorf("vote = %+v, want sender %d on block %x", v, vote.GetSender(), vote.GetVoteInfo().GetId())
			}
			m = recv(t, p.q)
		} else if uint32(i+1) == to {
			t.Errorf("replica %d: got %T before the vote", to, m)
		}
		if _, ok := m.(*diempb.TimeoutMsg); !ok {
			t.Errorf("replica %d: got %T, want the closing timeout", i+1, m)
		}
	}
}

// TestVoteToUnknownReplicaIsDropped: the peer configuration has no node for
// that ID, so the send is counted rather than panicking on a nil node.
func TestVoteToUnknownReplicaIsDropped(t *testing.T) {
	const n = 4
	peers := newGroup(t, n, record)
	_, vote, _ := round1(t, 1, n)

	before := peers[0].tr.Counters().OutboundDropped
	peers[0].tr.Vote(vote, uint32(n+1))

	if !waitFor(recvTimeout, func() bool { return peers[0].tr.Counters().OutboundDropped > before }) {
		t.Errorf("OutboundDropped = %d, want > %d", peers[0].tr.Counters().OutboundDropped, before)
	}
}

// TestForgedNeverReachesTheHandler sends a forged proposal and then the real
// one from the same sender. Gorums keeps one sender's requests in order, so the
// first message a handler sees is the real one only if the forgery was dropped
// in front of it. It covers a server New builds and one from NewLocalServers.
func TestForgedNeverReachesTheHandler(t *testing.T) {
	alone := func(t *testing.T) []*peer {
		p := &peer{id: 1, q: make(chan any, 8), tr: New(Config{
			ID: 1, Listen: "127.0.0.1:0",
			Peers:    map[uint32]string{1: "127.0.0.1:0"},
			Verifier: diem.NewVerifier(signer(t, 1, 1), diem.QuorumSize(1)),
		})}
		t.Cleanup(p.tr.Stop)
		record(p)
		return []*peer{p}
	}
	group := func(t *testing.T) []*peer { return newGroup(t, 4, record) }

	for _, tc := range []struct {
		name  string
		peers func(*testing.T) []*peer
	}{
		{"server built by New", alone},
		{"server from NewLocalServers", group},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peers := tc.peers(t)
			n := len(peers)
			proposal, _, _ := round1(t, 1, n)
			forged := proto.Clone(proposal).(*diempb.ProposalMsg)
			forged.SetSig(diempb.Signature_builder{Signer: 1, Sig: []byte("forged")}.Build())

			peers[0].tr.Proposal(forged)
			peers[0].tr.Proposal(proposal)
			for i, p := range peers {
				if m, _ := recv(t, p.q).(proto.Message); !proto.Equal(m, proposal) {
					t.Errorf("replica %d: first message is not the real proposal", i+1)
				}
			}
			// A local group shares one counter, so every replica reports all n.
			for i, p := range peers {
				if got := p.tr.Counters().Rejected; got != uint64(n) {
					t.Errorf("replica %d: Rejected = %d, want %d", i+1, got, n)
				}
			}
		})
	}
}

// TestVerifyInterceptor drives the interceptor directly, with no server
// involved. A rejected message must be counted and must not reach the next
// handler, and a valid one, or a request it does not verify, must pass. This
// is the test that shows the transport boundary is the security boundary.
func TestVerifyInterceptor(t *testing.T) {
	const n = 4
	var rejected atomic.Uint64
	verify := VerifyInterceptor(diem.NewVerifier(signer(t, 1, n), diem.QuorumSize(n)), &rejected)
	proposal, vote, timeout := round1(t, 1, n)

	forged := diempb.Signature_builder{Signer: 1, Sig: []byte("forged")}.Build()

	steps := []struct {
		name string
		msg  func() proto.Message
		pass bool
	}{
		{"proposal with no block", func() proto.Message {
			return diempb.ProposalMsg_builder{Sender: 1, Sig: forged}.Build()
		}, false},
		{"proposal whose signature does not verify", func() proto.Message {
			in := proto.Clone(proposal).(*diempb.ProposalMsg)
			in.SetSig(forged)
			return in
		}, false},
		{"proposal whose sender is not its signer", func() proto.Message {
			in := proto.Clone(proposal).(*diempb.ProposalMsg)
			in.SetSender(2)
			return in
		}, false},
		{"vote whose signature does not verify", func() proto.Message {
			in := proto.Clone(vote).(*diempb.VoteMsg)
			in.SetSig(forged)
			return in
		}, false},
		{"vote whose vote info was swapped behind the hash", func() proto.Message {
			in := proto.Clone(vote).(*diempb.VoteMsg)
			in.GetVoteInfo().SetRound(99)
			return in
		}, false},
		{"timeout with no tmo info", func() proto.Message {
			return diempb.TimeoutMsg_builder{}.Build()
		}, false},
		{"timeout whose signature does not verify", func() proto.Message {
			in := proto.Clone(timeout).(*diempb.TimeoutMsg)
			in.GetTmoInfo().SetSig(forged)
			return in
		}, false},
		{"valid proposal", func() proto.Message { return proto.Clone(proposal) }, true},
		{"valid vote", func() proto.Message { return proto.Clone(vote) }, true},
		{"valid timeout", func() proto.Message { return proto.Clone(timeout) }, true},
		{"block request", func() proto.Message { return diempb.BlockHash_builder{}.Build() }, true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			before := rejected.Load()
			passed := false
			next := func(gorums.ServerContext, *gorums.Message) (*gorums.Message, error) {
				passed = true
				return nil, nil
			}
			if _, err := verify(gorums.ServerContext{}, &gorums.Message{Proto: step.msg()}, next); err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if passed != step.pass {
				t.Errorf("reached the handler = %v, want %v", passed, step.pass)
			}
			want := before
			if !step.pass {
				want++
			}
			if got := rejected.Load(); got != want {
				t.Errorf("rejected = %d, want %d", got, want)
			}
		})
	}
}

// TestHandlerAcceptsWellFormed: well-formed messages of each type must reach
// the core, and each shows in its state. The proposal leaves its block in the
// tree, a quorum of timeouts moves the core to round 2 on a TC, and then a
// quorum of votes for the proposal forms a QC.
func TestHandlerAcceptsWellFormed(t *testing.T) {
	const n = 4
	core, mu := newCore(t, 2)
	h := &handler{core: core, mu: mu}
	state := func() diem.State {
		mu.Lock()
		defer mu.Unlock()
		return core.State()
	}
	proposal, _, _ := round1(t, 1, n)
	blk := proposal.GetBlock()

	h.Proposal(gorums.ServerContext{}, proposal)
	mu.Lock()
	held := core.Block(blk.GetId())
	mu.Unlock()
	if held == nil {
		t.Error("the proposal's block did not reach the core")
	}

	for _, from := range []uint32{1, 3, 4} {
		_, _, timeout := round1(t, from, n)
		h.Timeout(gorums.ServerContext{}, timeout)
	}
	if got := state().Round; got != 2 {
		t.Errorf("round = %d after a quorum of timeouts, want 2", got)
	}

	for _, from := range []uint32{1, 3, 4} {
		h.Vote(gorums.ServerContext{}, voteOn(t, from, n, blk))
	}
	if got := state().HighQCRound; got != 1 {
		t.Errorf("high QC round = %d after a quorum of votes, want 1", got)
	}
}

// newCore is a started core for replica id of 4 that sends nothing, with the
// lock it is called under. Its round timer is long enough never to fire in a
// test.
func newCore(t *testing.T, id uint32) (*diem.Core, *sync.Mutex) {
	t.Helper()
	mu := new(sync.Mutex)
	c := diem.New(diem.Config{
		ID:         id,
		Validators: []uint32{1, 2, 3, 4},
		Ledger:     diem.NewMemLedger(),
		Crypto:     signer(t, id, 4),
		Transport:  nopNet{},
		Clock:      diem.SystemClock{},
		Backoff:    diem.NewBackoff(time.Hour, time.Hour, 2),
		Lock:       mu,
	})
	mu.Lock()
	c.Start()
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		c.Stop()
		mu.Unlock()
	})
	return c, mu
}

type nopNet struct{}

func (nopNet) Proposal(*diempb.ProposalMsg) {}
func (nopNet) Vote(*diempb.VoteMsg, uint32) {}
func (nopNet) Timeout(*diempb.TimeoutMsg)   {}
func (nopNet) RequestBlock([]byte)          {}

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
			// Replica 2 asks; it does not lead round 1, so its core holds no
			// block of its own. The others answer with what they hold.
			core, mu := newCore(t, 2)
			held := map[uint32]*diempb.Block{1: forged, 3: nil, 4: tc.held}
			peers := newGroup(t, n, func(p *peer) {
				if p.id == 2 {
					p.tr.Start(core, mu)
					return
				}
				p.tr.serve(&recorder{q: p.q, held: held[p.id]})
			})

			peers[1].tr.fetch(peers[1].tr.peers(), want.GetId())

			mu.Lock()
			got := core.Block(want.GetId())
			mu.Unlock()
			if tc.held == nil {
				if got != nil {
					t.Fatalf("a fetch no correct peer answered reached the core with %+v", got)
				}
				return
			}
			if !proto.Equal(got, want) {
				t.Fatalf("the core holds %+v, want the requested block", got)
			}
		})
	}
}

// TestStopIdempotent checks Stop is safe to call twice, whether or not Start
// was ever called.
func TestStopIdempotent(t *testing.T) {
	newTransport := func() *Transport {
		return New(Config{
			ID: 1, Listen: "127.0.0.1:0",
			Peers:    map[uint32]string{1: "127.0.0.1:0"},
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
		tr.serve(&recorder{q: make(chan any, 1)})
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
	commits []*diempb.Block
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
	privs, pubs, err := diemcrypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	srvs, rejected, stopSrvs := localServers(t, n, diemcrypto.New(nil, pubs))
	t.Cleanup(stopSrvs)
	validators := make([]uint32, n)
	for i := range n {
		validators[i] = uint32(i + 1)
	}

	nodes := make([]*node, n)
	for i := range n {
		id := uint32(i + 1)
		nd := &node{id: id}
		signer := diemcrypto.New(privs[id], pubs)
		ledger := diem.NewMemLedger()
		ledger.OnCommit = func(b *diempb.Block) { nd.commits = append(nd.commits, b) }
		nd.tr = New(Config{
			ID: id, Server: srvs[i], Rejected: rejected,
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
// Stopping takes the transports down first, since a core call waiting on a
// send holds mu, then stops every core under its mu, because Gorums never
// waits for its handler goroutines. It is idempotent, so a test can both
// defer it and call it early to quiesce the cluster before reading core state.
func run(t *testing.T, nodes []*node) func() {
	t.Helper()
	for _, nd := range nodes {
		nd.mu.Lock()
		nd.tr.Start(nd.core, &nd.mu)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	for _, nd := range nodes {
		if err := nd.tr.WaitForPeers(waitCtx); err != nil {
			for _, nd := range nodes {
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
				nd.tr.Stop()
			}
			for _, nd := range nodes {
				nd.mu.Lock()
				nd.core.Stop()
				nd.mu.Unlock()
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
			if !bytes.Equal(log[k].ParentID(), log[k-1].GetId()) {
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

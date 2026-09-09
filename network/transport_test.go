package network

import (
	"context"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/hotstuffpb"
	"github.com/relab/gorums"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const recvTimeout = 5 * time.Second

// recv reads one event off q, failing the test after a generous timeout
// rather than blocking forever on a bug.
func recv(t *testing.T, q hotstuff.Queue) hotstuff.Event {
	t.Helper()
	select {
	case e := <-q:
		return e
	case <-time.After(recvTimeout):
		t.Fatal("timed out waiting for an event")
		return nil
	}
}

// drained reports whether q is empty right now. Handler calls in these tests
// run synchronously on the calling goroutine, so there is nothing to wait for.
func drained(q hotstuff.Queue) bool {
	select {
	case <-q:
		return false
	default:
		return true
	}
}

type replica struct {
	tr    *Transport
	q     hotstuff.Queue
	store *blockchain.Store
}

// newGroup builds n Gorums-local replicas wired into one peer group and
// starts them, registering cleanup to stop everything in the right order.
// GORUMS: peer addresses must all be known before any server is constructed,
// so this binds n real loopback listeners via NewLocalServers rather than
// letting each transport pick its own port.
func newGroup(t *testing.T, n int, fetchTimeout time.Duration) []*replica {
	t.Helper()
	srvs, stop, err := gorums.NewLocalServers(n,
		gorums.WithLocalDialOptions(gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	leader := hotstuff.RoundRobin(n)
	reps := make([]*replica, n)
	for i := range n {
		id := hotstuff.ID(i + 1)
		q := hotstuff.NewQueue(256)
		store := blockchain.New()
		reps[i] = &replica{
			tr: New(Config{
				ID: id, Server: srvs[i], Sink: q, Store: store,
				Verifier:     hotstuff.NewVerifier(nocrypto.New(id, n), leader),
				FetchTimeout: fetchTimeout,
			}),
			q:     q,
			store: store,
		}
	}
	for _, r := range reps {
		r.tr.Start()
	}
	t.Cleanup(func() {
		for _, r := range reps {
			r.tr.Stop()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i, r := range reps {
		if err := r.tr.WaitForPeers(ctx); err != nil {
			t.Fatalf("replica %d WaitForPeers: %v", i+1, err)
		}
	}
	return reps
}

// TestMulticastReachesAll checks that for each of Propose/Vote/Timeout, one
// replica sends and all four - the sender included - receive exactly the
// matching event type with the right contents.
//
// The sender receiving its own message over the same in-process local node is
// what deletes the "am I the next leader, collect my own vote locally"
// special case: every replica's inbound path is identical regardless of who
// sent the message.
func TestMulticastReachesAll(t *testing.T) {
	const n = 4
	reps := newGroup(t, n, 0)
	leader := hotstuff.RoundRobin(n)

	view := hotstuff.View(1)
	proposer := leader(view)
	blk := hotstuff.NewBlock(hotstuff.GenesisHash(), view, proposer, genesisQC(), [][]byte{[]byte("x")})
	psig, err := nocrypto.New(proposer, n).Sign(blk.Hash())
	if err != nil {
		t.Fatal(err)
	}
	vsig, err := nocrypto.New(1, n).Sign(hotstuff.VoteDigest(view, blk.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	tsig, err := nocrypto.New(2, n).Sign(hotstuff.TimeoutDigest(view))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		sender int // 0-based index into reps
		send   func(r *replica)
		check  func(t *testing.T, e hotstuff.Event)
	}{
		{
			name:   "Propose",
			sender: int(proposer) - 1,
			send: func(r *replica) {
				r.tr.Propose(hotstuff.Proposal{Block: blk, Sig: psig})
			},
			check: func(t *testing.T, e hotstuff.Event) {
				p, ok := e.(hotstuff.ProposeEvent)
				if !ok {
					t.Fatalf("got %T, want ProposeEvent", e)
				}
				if p.Block.Hash() != blk.Hash() {
					t.Errorf("block hash = %x, want %x", p.Block.Hash(), blk.Hash())
				}
			},
		},
		{
			name:   "Vote",
			sender: 0,
			send: func(r *replica) {
				r.tr.Vote(hotstuff.PartialCert{View: view, BlockHash: blk.Hash(), Sig: vsig})
			},
			check: func(t *testing.T, e hotstuff.Event) {
				v, ok := e.(hotstuff.VoteEvent)
				if !ok {
					t.Fatalf("got %T, want VoteEvent", e)
				}
				if v.View != view || v.BlockHash != blk.Hash() || v.Sig.Signer != 1 {
					t.Errorf("vote = %+v, want view %d hash %x signer 1", v.PartialCert, view, blk.Hash())
				}
			},
		},
		{
			name:   "Timeout",
			sender: 2,
			send: func(r *replica) {
				r.tr.Timeout(hotstuff.TimeoutMsg{View: view, Sig: tsig, HighQC: genesisQC()})
			},
			check: func(t *testing.T, e hotstuff.Event) {
				m, ok := e.(hotstuff.TimeoutEvent)
				if !ok {
					t.Fatalf("got %T, want TimeoutEvent", e)
				}
				if m.View != view || m.Sig.Signer != 2 {
					t.Errorf("timeout = %+v, want view %d signer 2", m.TimeoutMsg, view)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.send(reps[tt.sender])
			for _, r := range reps {
				tt.check(t, recv(t, r.q))
			}
		})
	}
}

// TestFetchReturnsStoredBlock has a replica lacking a block fetch it
// from one that has it, and the resulting event's block hashes correctly.
func TestFetchReturnsStoredBlock(t *testing.T) {
	const n = 4
	reps := newGroup(t, n, 0)

	blk := hotstuff.NewBlock(hotstuff.GenesisHash(), 1, 1, genesisQC(), [][]byte{[]byte("y")})
	reps[0].store.Put(blk)
	reps[1].store.Put(blk)
	// reps[2] and reps[3] do not have it; reps[3] fetches.

	reps[3].tr.Fetch(blk.Hash())
	e := recv(t, reps[3].q)
	f, ok := e.(hotstuff.FetchedEvent)
	if !ok {
		t.Fatalf("got %T, want FetchedEvent", e)
	}
	if f.Block.Hash() != blk.Hash() {
		t.Errorf("fetched hash = %x, want %x", f.Block.Hash(), blk.Hash())
	}
}

// TestFetchUnknownHashFails: nobody holds the requested block, so
// the fetch times out, counts a failure, and pushes nothing. FetchTimeout is
// kept short so the test stays fast.
func TestFetchUnknownHashFails(t *testing.T) {
	const n = 4
	reps := newGroup(t, n, 50*time.Millisecond)

	var unknown hotstuff.Hash
	unknown[0] = 0xFF

	reps[0].tr.Fetch(unknown)

	select {
	case e := <-reps[0].q:
		t.Fatalf("got %T, want no event", e)
	case <-time.After(300 * time.Millisecond):
	}
	if got := reps[0].tr.Counters().FetchFailed; got == 0 {
		t.Errorf("FetchFailed = %d, want > 0", got)
	}
}

// TestHandlerRejectsMalformed drives the handler directly, with
// no server involved. Each row is converter- or verifier-rejected, and each
// must increment rejected without pushing an event. This is the test that
// shows the transport boundary is the security boundary.
func TestHandlerRejectsMalformed(t *testing.T) {
	const n = 4
	leader := hotstuff.RoundRobin(n)
	ver := hotstuff.NewVerifier(nocrypto.New(1, n), leader)
	q := hotstuff.NewQueue(8)
	store := blockchain.New()
	h := &handler{ver: ver, sink: q, store: store}

	view := hotstuff.View(1)
	proposer := leader(view)
	goodBlock := hotstuff.NewBlock(hotstuff.GenesisHash(), view, proposer, genesisQC(), nil)
	validSig := hotstuffpb.Signature_builder{Signer: 1, Sig: []byte("s")}.Build()

	steps := []struct {
		name string
		run  func()
	}{
		{"nil-block proposal", func() {
			h.Propose(gorums.ServerContext{}, hotstuffpb.Proposal_builder{Sig: validSig}.Build())
		}},
		{"proposal whose signature does not verify", func() {
			in := hotstuffpb.Proposal_builder{
				Block: toBlock(goodBlock),
				Sig:   hotstuffpb.Signature_builder{Signer: uint32(proposer), Sig: []byte("bogus")}.Build(),
			}.Build()
			h.Propose(gorums.ServerContext{}, in)
		}},
		{"vote at view 0", func() {
			zsig, err := nocrypto.New(1, n).Sign(hotstuff.VoteDigest(0, goodBlock.Hash()))
			if err != nil {
				t.Fatal(err)
			}
			h.Vote(gorums.ServerContext{}, toVote(hotstuff.PartialCert{View: 0, BlockHash: goodBlock.Hash(), Sig: zsig}))
		}},
		{"timeout with a nil HighQc", func() {
			in := hotstuffpb.TimeoutMsg_builder{View: 1, Sig: validSig}.Build()
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

// TestHandlerFetch drives handler.Fetch directly with a zero
// gorums.ServerContext, whose Release is nil-safe.
func TestHandlerFetch(t *testing.T) {
	store := blockchain.New()
	blk := hotstuff.NewBlock(hotstuff.GenesisHash(), 1, 1, genesisQC(), [][]byte{[]byte("z")})
	store.Put(blk)
	h := &handler{store: store}

	t.Run("stored hash", func(t *testing.T) {
		resp, err := h.Fetch(gorums.ServerContext{}, toBlockHash(blk.Hash()))
		if err != nil {
			t.Fatal(err)
		}
		got, err := fromBlock(resp)
		if err != nil {
			t.Fatal(err)
		}
		if got.Hash() != blk.Hash() {
			t.Errorf("fetched hash = %x, want %x", got.Hash(), blk.Hash())
		}
	})

	t.Run("unknown hash", func(t *testing.T) {
		var unknown hotstuff.Hash
		unknown[0] = 0xEE
		if _, err := h.Fetch(gorums.ServerContext{}, toBlockHash(unknown)); err == nil {
			t.Error("got nil error, want non-nil")
		}
	})
}

// TestOutboundQueueDrops never calls Start, so
// nothing drains the outbound queue; sends must drop rather than block.
// Outbound drops are safe because loss is what the view timer recovers from,
// while the inbound queue (hotstuff.Queue) is bounded and blocking for the
// opposite reason: an already-accepted event must never be lost.
func TestOutboundQueueDrops(t *testing.T) {
	const n = 1
	id := hotstuff.ID(1)
	tr := New(Config{
		ID: id, Listen: ":0", OutQueue: 1,
		// This replica's own ID resolves to an in-process node regardless of
		// the address given, so the placeholder is never dialed.
		Peers:    map[uint32]string{uint32(id): "127.0.0.1:0"},
		Sink:     hotstuff.NewQueue(8),
		Store:    blockchain.New(),
		Verifier: hotstuff.NewVerifier(nocrypto.New(id, n), hotstuff.RoundRobin(n)),
	})
	t.Cleanup(tr.Stop)

	done := make(chan struct{})
	go func() {
		for range 5 {
			tr.Propose(hotstuff.Proposal{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(recvTimeout):
		t.Fatal("Propose blocked instead of dropping")
	}

	if got := tr.Counters().OutboundDropped; got == 0 {
		t.Errorf("OutboundDropped = %d, want > 0", got)
	}
}

// TestStopIdempotent checks Stop is safe to call twice, whether or not
// Start was ever called.
func TestStopIdempotent(t *testing.T) {
	newTransport := func() *Transport {
		return New(Config{
			ID: 1, Listen: ":0",
			Peers:    map[uint32]string{1: "127.0.0.1:0"},
			Sink:     hotstuff.NewQueue(1),
			Store:    blockchain.New(),
			Verifier: hotstuff.NewVerifier(nocrypto.New(1, 1), hotstuff.RoundRobin(1)),
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

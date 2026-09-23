package network

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/hotstuffpb"
	"github.com/relab/gorums"
)

const (
	defaultOutQueue     = 1024
	defaultFetchTimeout = 2 * time.Second
)

// Config is what the transport and its inbound handlers need.
type Config struct {
	ID       hotstuff.ID
	Peers    map[uint32]string // every replica's address, this one included
	Listen   string            // ":0" picks a free port; read it back with Addr
	Sink     hotstuff.EventSink
	Verifier *hotstuff.Verifier
	Store    *blockchain.Store

	OutQueue      int           // outbound queue depth; 0 picks a default
	FetchTimeout  time.Duration // bounds one backfill quorum call; 0 picks a default
	DialOptions   []gorums.DialOption
	ServerOptions []gorums.ServerOption

	// Server, if set, is used instead of creating one, and Listen, Peers,
	// DialOptions and ServerOptions are then ignored. That is how
	// gorums.NewLocalServers is used: WithPeers needs every peer address before
	// any server exists, so the listeners have to be allocated first.
	Server *gorums.Server
}

// call performs one outbound Gorums call against the peer configuration.
type call func(*gorums.ConfigContext)

// peerAddr adapts a plain address to gorums.NodeAddress.
// GORUMS: WithNodes requires an Addr() string method, so a map[uint32]string
// cannot be handed over directly; and WithNodeList, the alternative, numbers
// nodes from a process-wide registry, so a second server in the same process
// would get IDs n+1..2n rather than 1..n.
type peerAddr string

func (a peerAddr) Addr() string { return string(a) }

// Transport is the Gorums implementation of hotstuff.Transport, together with
// the server that receives on the other side.
//
// Outbound is bounded and dropping; inbound is bounded and blocking. The
// asymmetry is deliberate: a dropped outbound message is what the view timer
// recovers from, while dropping an event the replica has already accepted is
// not recoverable.
type Transport struct {
	srv     *gorums.Server
	sink    hotstuff.EventSink
	handler *handler
	out     chan call
	timeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dropped  atomic.Uint64
	fetchErr atomic.Uint64
}

var _ hotstuff.Transport = (*Transport)(nil)

// New builds the Gorums server, registers the inbound handlers and returns the
// transport over it. Nothing is served until Start.
func New(cfg Config) *Transport {
	if cfg.OutQueue == 0 {
		cfg.OutQueue = defaultOutQueue
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = defaultFetchTimeout
	}

	// GORUMS, in its favour: WithPeers makes this replica's own ID an in-process
	// local node, so Algorithm 4's "broadcast to all replicas, including u
	// itself" works literally. The leader's own proposal returns as a normal
	// inbound event, which is what lets the core delete relab's "am I the next
	// leader, so collect my own vote locally" branch rather than reimplement it.
	srv := cfg.Server
	if srv == nil {
		peers := make(map[uint32]peerAddr, len(cfg.Peers))
		for id, addr := range cfg.Peers {
			peers[id] = peerAddr(addr)
		}
		srv = gorums.NewServer(append([]gorums.ServerOption{
			gorums.WithAddr(cfg.Listen),
			gorums.WithPeers(uint32(cfg.ID), gorums.WithNodes(peers), cfg.DialOptions...),
		}, cfg.ServerOptions...)...)
	}
	h := &handler{ver: cfg.Verifier, sink: cfg.Sink, store: cfg.Store}
	// Register before anything serves. GORUMS: Server.RegisterHandler writes an
	// unsynchronised map that the inbound manager reads once serving starts, so
	// gorumstest.LocalServers — which serves before it returns — cannot be used
	// for a replica group; -race flags it.
	hotstuffpb.RegisterHotStuffServer(srv, h)

	ctx, cancel := context.WithCancel(context.Background())
	return &Transport{
		srv:     srv,
		sink:    cfg.Sink,
		handler: h,
		out:     make(chan call, cfg.OutQueue),
		timeout: cfg.FetchTimeout,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start serves inbound requests and begins draining the outbound queue. It
// returns immediately.
func (t *Transport) Start() {
	t.wg.Add(2)
	go func() {
		defer t.wg.Done()
		_ = t.srv.ListenAndServe() // returns when Stop closes the listener
	}()
	go func() {
		defer t.wg.Done()
		t.drain()
	}()
}

// Stop shuts the server down and waits for the sender to finish. In-flight
// backfills are cancelled; stop the consensus loop before calling this.
func (t *Transport) Stop() {
	t.cancel()
	t.srv.Stop()
	t.wg.Wait()
}

// Addr is the address the server listens on, which is how a ":0" listener
// reports the port it got.
func (t *Transport) Addr() string { return t.srv.Addr() }

// WaitForPeers blocks until every configured peer has connected, or ctx is done.
func (t *Transport) WaitForPeers(ctx context.Context) error {
	want := t.srv.PeerConfig().Size()
	return t.srv.WaitForPeers(ctx, func(c gorums.Config) bool { return c.Size() >= want })
}

func (t *Transport) Propose(p hotstuff.Proposal) {
	msg := toProposal(p)
	t.enqueue(func(ctx *gorums.ConfigContext) { _ = hotstuffpb.Propose(ctx, msg).Send() })
}

func (t *Transport) Vote(cert hotstuff.PartialCert) {
	msg := toVote(cert)
	t.enqueue(func(ctx *gorums.ConfigContext) { _ = hotstuffpb.Vote(ctx, msg).Send() })
}

func (t *Transport) Timeout(m hotstuff.TimeoutMsg) {
	msg := toTimeout(m)
	t.enqueue(func(ctx *gorums.ConfigContext) { _ = hotstuffpb.Timeout(ctx, msg).Send() })
}

// Fetch backfills a block by hash. It returns at once; the answer arrives as a
// FetchedEvent, or never.
func (t *Transport) Fetch(h hotstuff.Hash) {
	cfg := t.peers()
	if cfg == nil || t.ctx.Err() != nil {
		t.dropped.Add(1)
		return
	}
	// Its own goroutine rather than the outbound queue: a quorum call waits for
	// a reply, and the queue has to keep moving. The core holds at most one
	// in-flight fetch per hash, so this is bounded by the number of gaps.
	go t.fetch(cfg, h)
}

func (t *Transport) fetch(cfg gorums.Config, want hotstuff.Hash) {
	ctx, cancel := context.WithTimeout(t.ctx, t.timeout)
	defer cancel()

	// GORUMS, in its favour: with QuorumSpec gone, aggregating responses is a
	// plain function over Responses — .First() here, and Results() for anything
	// stateful — rather than a method on a shoehorned interface.
	resp, err := hotstuffpb.Fetch(cfg.Context(ctx), toBlockHash(want)).First()
	if err != nil {
		t.fetchErr.Add(1)
		return
	}
	b, err := fromBlock(resp)
	if err != nil {
		t.fetchErr.Add(1)
		return
	}
	// Re-hashing is mandatory, not defensive: .First() accepts whichever single
	// reply arrives first, so content is the only thing that authenticates it.
	if b.Hash() != want {
		t.fetchErr.Add(1)
		return
	}
	if t.ctx.Err() != nil {
		return
	}
	t.sink.Push(hotstuff.FetchedEvent{Block: b})
}

// enqueue never blocks: an outbound message is dropped rather than delayed,
// and the drop is counted.
func (t *Transport) enqueue(fn call) {
	select {
	case t.out <- fn:
	default:
		t.dropped.Add(1)
	}
}

func (t *Transport) drain() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case fn := <-t.out:
			cfg := t.peers()
			if cfg == nil {
				t.dropped.Add(1)
				continue
			}
			// GORUMS: a one-way Send blocks once a node's send queue fills, and
			// Async is the only alternative, so the bounded queue in front of
			// this goroutine is what keeps the consensus goroutine free.
			fn(cfg.Context(t.ctx))
		}
	}
}

// peers is the peer configuration, or nil when it is empty.
// GORUMS: Config.Context panics on an empty Config, so this guard is not
// optional — which is why it lives in exactly one place.
func (t *Transport) peers() gorums.Config {
	cfg := t.srv.PeerConfig()
	if cfg.Size() == 0 {
		return nil
	}
	return cfg
}

// Counters is a snapshot of what the transport had to discard. A BFT replica
// cannot act on a send error, so counting is what happens instead.
type Counters struct {
	OutboundDropped uint64
	FetchFailed     uint64
	Rejected        uint64
}

func (t *Transport) Counters() Counters {
	return Counters{
		OutboundDropped: t.dropped.Load(),
		FetchFailed:     t.fetchErr.Load(),
		Rejected:        t.handler.rejected.Load(),
	}
}

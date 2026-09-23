package diemnet

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
)

const defaultOutQueue = 1024

// Config is what the transport and its inbound handlers need.
type Config struct {
	ID       diem.ID
	Peers    map[uint32]string // every replica's address, this one included
	Listen   string            // ":0" picks a free port; read it back with Addr
	Sink     func(diem.Event)  // where verified inbound events go
	Verifier *diem.Verifier

	OutQueue      int // outbound queue depth; 0 picks a default
	DialOptions   []gorums.DialOption
	ServerOptions []gorums.ServerOption

	// Server, if set, is used instead of creating one, and Listen, Peers,
	// DialOptions and ServerOptions are then ignored. That is how
	// gorums.NewLocalServers is used: WithPeers needs every peer address before
	// any server exists, so the listeners have to be allocated first.
	Server *gorums.Server
}

// call performs one outbound Gorums call against the peer configuration. It
// runs on the sender goroutine, which is also where a unicast's node lookup
// happens.
type call func(gorums.Config)

// peerAddr adapts a plain address to gorums.NodeAddress.
// GORUMS: WithNodes requires an Addr() string method, so a map[uint32]string
// cannot be handed over directly; and WithNodeList, the alternative, numbers
// nodes from a process-wide registry, so a second server in the same process
// would get IDs n+1..2n rather than 1..n.
type peerAddr string

func (a peerAddr) Addr() string { return string(a) }

// Transport is the Gorums implementation of diem.Transport, together with the
// server that receives on the other side.
//
// Outbound is bounded and dropping; inbound is bounded and blocking. The
// asymmetry is deliberate: a dropped outbound message is what the round timer
// recovers from, while dropping an event the replica has already accepted is
// not recoverable.
//
// There is no backfill call. DiemBFT §3 defines no block-sync, so a replica
// that loses a proposal has nothing to ask for; it declines to vote and
// diem.Safety.DeclinedMissingAncestor counts what that costs.
type Transport struct {
	srv     *gorums.Server
	handler *handler
	out     chan call

	// nodes indexes the peer configuration by replica ID for unicast. It is
	// written and read only by the sender goroutine, so it needs no lock.
	nodes map[uint32]*gorums.Node

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dropped atomic.Uint64
}

var _ diem.Transport = (*Transport)(nil)

// New builds the Gorums server, registers the inbound handlers and returns the
// transport over it. Nothing is served until Start.
func New(cfg Config) *Transport {
	if cfg.OutQueue == 0 {
		cfg.OutQueue = defaultOutQueue
	}

	// GORUMS, in its favour: WithPeers makes this replica's own ID an in-process
	// local node, so the paper's "broadcast to all replicas, including u itself"
	// works literally. A leader's own proposal returns as a normal inbound
	// event, which is what lets Core treat every message the same way whoever
	// sent it.
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
	h := &handler{ver: cfg.Verifier, sink: cfg.Sink}
	// Register before anything serves. GORUMS: Server.RegisterHandler writes an
	// unsynchronised map that the inbound manager reads once serving starts, so
	// gorumstest.LocalServers — which serves before it returns — cannot be used
	// for a replica group; -race flags it.
	diempb.RegisterDiemServer(srv, h)

	ctx, cancel := context.WithCancel(context.Background())
	return &Transport{
		srv:     srv,
		handler: h,
		out:     make(chan call, cfg.OutQueue),
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

// Stop shuts the server down and waits for the sender to finish. Stop the
// consensus loop before calling this.
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

func (t *Transport) Proposal(p *diem.ProposalMsg) {
	msg := toProposal(p)
	t.enqueue(func(cfg gorums.Config) { _ = diempb.Proposal(cfg.Context(t.ctx), msg).Send() })
}

// Vote unicasts to the leader of the next round, as the paper does: that leader
// is the only replica that will propose over the certificate these votes form.
func (t *Transport) Vote(v *diem.VoteMsg, to diem.ID) {
	msg := toVote(v)
	t.enqueue(func(cfg gorums.Config) {
		node := t.node(cfg, uint32(to))
		if node == nil {
			t.dropped.Add(1)
			return
		}
		_ = diempb.Vote(node.Context(t.ctx), msg).Send()
	})
}

func (t *Transport) Timeout(m *diem.TimeoutMsg) {
	msg := toTimeout(m)
	t.enqueue(func(cfg gorums.Config) { _ = diempb.Timeout(cfg.Context(t.ctx), msg).Send() })
}

// node resolves a replica ID to the Gorums node to unicast to, indexing the
// peer configuration on first use.
//
// GORUMS: Config offers Nodes() and Node.ID() but no Node(id) accessor, so an
// ID-addressed send would otherwise scan the whole configuration once per vote
// — the protocol's most frequent message. The peer set is fixed when the server
// is built, so one index serves the whole run.
func (t *Transport) node(cfg gorums.Config, id uint32) *gorums.Node {
	if t.nodes == nil {
		t.nodes = make(map[uint32]*gorums.Node, cfg.Size())
		for _, n := range cfg.Nodes() {
			t.nodes[n.ID()] = n
		}
	}
	return t.nodes[id]
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
			fn(cfg)
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
	Rejected        uint64
}

func (t *Transport) Counters() Counters {
	return Counters{
		OutboundDropped: t.dropped.Load(),
		Rejected:        t.handler.rejected.Load(),
	}
}

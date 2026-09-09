// Package replica wires a HotStuff replica together and owns its lifecycle.
package replica

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/consensus"
	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/metrics"
	"github.com/DanyGoT/HotStuffs/network"
	"github.com/relab/gorums"
)

const (
	defaultQueueSize    = 4096
	defaultViewDuration = 500 * time.Millisecond
	backoffFactor       = 2
)

// Config is everything a replica needs.
type Config struct {
	ID     hotstuff.ID
	Peers  map[uint32]string // every replica's address, this one included
	Listen string            // ":0" picks a free port; read it back with Addr

	Key  *ecdsa.PrivateKey
	Keys map[hotstuff.ID]*ecdsa.PublicKey

	Commands hotstuff.CommandQueue // nil proposes empty blocks

	QueueSize       int
	ViewDuration    time.Duration
	MaxViewDuration time.Duration

	// Server, if set, is the Gorums server to run on, as gorums.NewLocalServers
	// provides for a single-process cluster. Peers and Listen are then unused.
	Server      *gorums.Server
	DialOptions []gorums.DialOption

	// Metrics, if set, is wrapped around the transport and the executor and
	// installed as the core's observer. The protocol is unchanged either way.
	Metrics *metrics.Metrics
}

// Replica is one HotStuff replica: a protocol core, its event loop, and the
// Gorums transport underneath.
type Replica struct {
	id   hotstuff.ID
	core *consensus.Core
	loop *consensus.Loop
	net  *network.Transport
	log  *hotstuff.MemLog
}

// New wires a replica. The order is forced by the constructors themselves: the
// event queue is the only dependency-free piece, so it comes first, and both
// the transport and the core then hang off it. That is what breaks the cycle
// between them without a DI framework.
func New(cfg Config) *Replica {
	if cfg.QueueSize == 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.ViewDuration == 0 {
		cfg.ViewDuration = defaultViewDuration
	}
	if cfg.MaxViewDuration == 0 {
		cfg.MaxViewDuration = 64 * cfg.ViewDuration
	}
	if cfg.Commands == nil {
		cfg.Commands = NoCommands{}
	}
	n := len(cfg.Keys) // the registered public keys are the replica set

	q := hotstuff.NewQueue(cfg.QueueSize)
	store := blockchain.New()
	log := hotstuff.NewMemLog()
	signer := crypto.New(cfg.ID, cfg.Key, cfg.Keys)
	leader := hotstuff.RoundRobin(n)

	net := network.New(network.Config{
		ID:          cfg.ID,
		Peers:       cfg.Peers,
		Listen:      cfg.Listen,
		Sink:        q,
		Verifier:    hotstuff.NewVerifier(signer, leader),
		Store:       store,
		Server:      cfg.Server,
		DialOptions: cfg.DialOptions,
	})

	var (
		transport hotstuff.Transport = net
		executor  hotstuff.Executor  = log
		observer  func(hotstuff.Event, hotstuff.State, time.Duration)
	)
	if cfg.Metrics != nil {
		transport, executor, observer = cfg.Metrics.Transport(net), cfg.Metrics.Executor(log), cfg.Metrics.Observe
	}

	core := consensus.New(consensus.Config{
		ID:        cfg.ID,
		N:         n,
		Rules:     consensus.NewRules(cfg.ID, store),
		Store:     store,
		Crypto:    signer,
		Transport: transport,
		Leader:    leader,
		Clock:     hotstuff.SystemClock{},
		Duration:  consensus.NewViewDuration(cfg.ViewDuration, cfg.MaxViewDuration, backoffFactor),
		Commands:  cfg.Commands,
		Executor:  executor,
		Sink:      q,
		Observer:  observer,
	})

	return &Replica{id: cfg.ID, core: core, loop: consensus.NewLoop(core, q), net: net, log: log}
}

// Run serves the transport, waits for every peer, then runs the consensus loop
// until ctx is done. Waiting for peers before the first beat matters: a
// proposal multicast into a half-connected configuration is simply lost, and
// the replica would then sit out a view for nothing. Cancelling ctx is how a
// replica stops; the transport is shut down after the loop, never before.
func (r *Replica) Run(ctx context.Context) error {
	r.net.Start()
	defer r.net.Stop()
	if err := r.net.WaitForPeers(ctx); err != nil {
		return err
	}
	r.core.Start()
	return r.loop.Run(ctx)
}

// ID is this replica's identity.
func (r *Replica) ID() hotstuff.ID { return r.id }

// Addr is the address the transport listens on.
func (r *Replica) Addr() string { return r.net.Addr() }

// Log is the committed blocks, in commit order. It is safe to call from any
// goroutine; the core's own state deliberately is not exposed, since it belongs
// to the loop goroutine alone.
func (r *Replica) Log() []*hotstuff.Block { return r.log.Snapshot() }

// Counters is what the transport had to discard.
func (r *Replica) Counters() network.Counters { return r.net.Counters() }

// QueueHighWater is the deepest the inbound event queue has been, which is what
// says whether inbound backpressure was ever felt.
func (r *Replica) QueueHighWater() int { return r.loop.QueueHighWater() }

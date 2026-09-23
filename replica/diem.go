package replica

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/diemnet"
	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Diem is one DiemBFT replica: a protocol core, its event loop, and the Gorums
// transport underneath. It is a sibling of Replica rather than a mode of it:
// the two protocols share the key loading, the peer configuration and the
// shutdown contract, and nothing else.
//
// Config.Metrics is ignored here. diem.Config.Observer is the same hook
// metrics.Observe uses on the other side, but it reports a diem.State, so
// wiring it up means a second metrics shape; that is deliberately left out.
type Diem struct {
	id   hotstuff.ID
	core *diem.Core
	loop *diem.Loop
	net  *diemnet.Transport
	q    diem.Queue

	// mu guards the commit log, which the ledger appends to on the consensus
	// goroutine and callers read from their own. It guards application state,
	// never protocol state.
	mu      sync.Mutex
	commits []*diem.Block

	// declined mirrors diem.State.DeclinedMissingAncestor out of the loop
	// goroutine, which is the only way to read it: the core's state is not
	// shared. It is the standing cost of DiemBFT 3 having no block-sync.
	declined atomic.Uint64
}

// NewDiem wires a DiemBFT replica. The order is the one Replica's constructor
// is forced into for the same reason: the event queue is the only
// dependency-free piece, so it comes first and both the transport and the core
// hang off it.
func NewDiem(cfg Config) *Diem {
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
	// The key set fixes the quorum and the leader rotation, so a peer list that
	// disagrees with it would give this replica a different quorum from its
	// peers. That is a deployment error to fail on, not to reconcile.
	if len(cfg.Peers) != 0 && len(cfg.Peers) != len(cfg.Keys) {
		panic(fmt.Sprintf("replica: %d peer addresses but %d public keys", len(cfg.Peers), len(cfg.Keys)))
	}
	if cfg.Keys[cfg.ID] == nil {
		panic(fmt.Sprintf("replica: no public key registered for this replica's own ID %d", cfg.ID))
	}

	validators := slices.Sorted(maps.Keys(cfg.Keys))
	signer := crypto.New(cfg.ID, cfg.Key, cfg.Keys)
	q := diem.NewQueue(cfg.QueueSize)

	r := &Diem{id: cfg.ID, q: q}
	ledger := diem.NewMemLedger()
	ledger.OnCommit = r.commit

	r.net = diemnet.New(diemnet.Config{
		ID:          cfg.ID,
		Peers:       cfg.Peers,
		Listen:      cfg.Listen,
		Sink:        q.Push,
		Verifier:    diem.NewVerifier(signer, hotstuff.QuorumSize(len(validators))),
		Server:      cfg.Server,
		DialOptions: cfg.DialOptions,
	})
	r.core = diem.New(diem.Config{
		ID:           cfg.ID,
		Validators:   validators,
		Ledger:       ledger,
		Crypto:       signer,
		Transport:    r.net,
		Clock:        hotstuff.SystemClock{},
		Duration:     hotstuff.NewDuration(cfg.ViewDuration, cfg.MaxViewDuration, backoffFactor),
		Sink:         q.Push,
		Transactions: transactions(cfg.Commands),
		Observer: func(_ diem.Event, s diem.State, _ time.Duration) {
			r.declined.Store(s.DeclinedMissingAncestor)
		},
	})
	r.loop = diem.NewLoop(r.core, q)
	return r
}

// transactions adapts a CommandQueue to the paper's MemPool.get_transactions
// (3.6). An empty batch still produces a block, so the "nothing to propose"
// signal is dropped: the pipeline is what commits the blocks below it.
func transactions(cmds hotstuff.CommandQueue) func() [][]byte {
	return func() [][]byte {
		txns, _ := cmds.Poll()
		return txns
	}
}

func (r *Diem) commit(b *diem.Block) {
	r.mu.Lock()
	r.commits = append(r.commits, b)
	r.mu.Unlock()
}

// Run serves the transport, waits for every peer, then runs the consensus loop
// until ctx is done. Waiting for peers before the first round matters: a
// proposal multicast into a half-connected configuration is simply lost, and
// with no block-sync in DiemBFT 3 the replicas that missed it never get it
// back. Cancelling ctx is how a replica stops; the transport is shut down after
// the loop, never before.
func (r *Diem) Run(ctx context.Context) error {
	r.net.Start()
	if err := r.net.WaitForPeers(ctx); err != nil {
		r.stop()
		return err
	}
	r.core.Start()
	err := r.loop.Run(ctx)
	r.stop()
	return err
}

// stop shuts the transport down and keeps the inbound queue moving while it
// does. That queue is bounded and blocking by design, so a handler parked on a
// push the loop has stopped answering never returns — and Gorums dispatches
// each handler on a goroutine it never waits for, so shutting down without
// draining simply strands them. Events read here are discarded: the core has
// stopped, and nothing can act on them.
func (r *Diem) stop() {
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		r.net.Stop()
	}()
	for {
		select {
		case <-stopped:
			// Whatever reached the queue before the transport went down is
			// still holding its producer; let the last of them through.
			for len(r.q) > 0 {
				<-r.q
			}
			return
		case <-r.q:
		}
	}
}

// ID is this replica's identity.
func (r *Diem) ID() hotstuff.ID { return r.id }

// Addr is the address the transport listens on.
func (r *Diem) Addr() string { return r.net.Addr() }

// Log is the committed blocks, in commit order. It is safe to call from any
// goroutine; the core's own state deliberately is not exposed, since it belongs
// to the loop goroutine alone.
func (r *Diem) Log() []*diem.Block {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*diem.Block(nil), r.commits...)
}

// Counters is what the transport had to discard.
func (r *Diem) Counters() diemnet.Counters { return r.net.Counters() }

// DeclinedMissingAncestor is how many votes this replica withheld because it
// never saw a block's ancestry. DiemBFT 3 defines no way to fetch the missing
// block, so a replica that loses one proposal cannot vote on its descendants
// either; this is the number that says what that costs.
func (r *Diem) DeclinedMissingAncestor() uint64 { return r.declined.Load() }

// QueueHighWater is the deepest the inbound event queue has been, which is what
// says whether inbound backpressure was ever felt.
func (r *Diem) QueueHighWater() int { return r.loop.QueueHighWater() }

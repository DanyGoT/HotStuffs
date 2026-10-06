// Package replica wires a DiemBFT replica together and owns its lifecycle.
package replica

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/diemnet"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
)

const (
	defaultQueueSize    = 4096
	defaultRoundTimeout = 500 * time.Millisecond
	backoffFactor       = 2
)

// Config is everything a replica needs.
type Config struct {
	ID     uint32
	Peers  map[uint32]string // every replica's address, this one included
	Listen string            // ":0" picks a free port; read it back with Addr

	Key  *ecdsa.PrivateKey
	Keys map[uint32]*ecdsa.PublicKey

	// Transactions supplies a leader's payload; nil proposes empty blocks.
	Transactions func() [][]byte

	QueueSize       int
	RoundTimeout    time.Duration
	MaxRoundTimeout time.Duration

	// Server, if set, is the Gorums server to run on, as gorums.NewLocalServers
	// provides for a single-process cluster. Peers and Listen are then unused.
	Server      *gorums.Server
	DialOptions []gorums.DialOption
}

// Replica is one DiemBFT replica: a protocol core, its event loop, and the
// Gorums transport underneath.
type Replica struct {
	id   uint32
	core *diem.Core
	loop *diem.Loop
	net  *diemnet.Transport
	q    diem.Queue

	// mu guards the commit log, which the ledger appends to on the consensus
	// goroutine and callers read from their own. It guards application state,
	// never protocol state.
	mu        sync.Mutex
	commits   []*diempb.Block
	latencies []time.Duration
	commands  uint64

	// proposed is when this replica sent its proposal for each round it led and
	// has not yet seen committed. Only the consensus goroutine touches it.
	proposed map[uint64]time.Time

	// declined mirrors diem.State.DeclinedMissingAncestor out of the loop
	// goroutine, which is the only way to read it: the core's state is not
	// shared. It is the standing cost of DiemBFT 3 having no block-sync.
	declined atomic.Uint64
}

// New wires a replica. The event queue is the only dependency-free piece, so it
// comes first, and both the transport and the core hang off it.
func New(cfg Config) *Replica {
	if cfg.QueueSize == 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.RoundTimeout == 0 {
		cfg.RoundTimeout = defaultRoundTimeout
	}
	if cfg.MaxRoundTimeout == 0 {
		cfg.MaxRoundTimeout = 64 * cfg.RoundTimeout
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
	signer := crypto.New(cfg.Key, cfg.Keys)
	q := diem.NewQueue(cfg.QueueSize)

	r := &Replica{id: cfg.ID, q: q, proposed: map[uint64]time.Time{}}
	ledger := diem.NewMemLedger()
	ledger.OnCommit = r.commit

	r.net = diemnet.New(diemnet.Config{
		ID:          cfg.ID,
		Peers:       cfg.Peers,
		Listen:      cfg.Listen,
		Sink:        q.Push,
		Verifier:    diem.NewVerifier(signer, diem.QuorumSize(len(validators))),
		Server:      cfg.Server,
		DialOptions: cfg.DialOptions,
	})
	r.core = diem.New(diem.Config{
		ID:           cfg.ID,
		Validators:   validators,
		Ledger:       ledger,
		Crypto:       signer,
		Transport:    stamper{r.net, r.proposed},
		Clock:        diem.SystemClock{},
		Backoff:      diem.NewBackoff(cfg.RoundTimeout, cfg.MaxRoundTimeout, backoffFactor),
		Sink:         q.Push,
		Transactions: cfg.Transactions,
		Observer: func(_ diem.Event, s diem.State, _ time.Duration) {
			r.declined.Store(s.DeclinedMissingAncestor)
		},
	})
	r.loop = diem.NewLoop(r.core, q)
	return r
}

// stamper records when this replica sends each of its proposals.
type stamper struct {
	*diemnet.Transport
	proposed map[uint64]time.Time
}

func (s stamper) Proposal(p *diempb.ProposalMsg) {
	s.proposed[p.GetBlock().GetRound()] = time.Now()
	s.Transport.Proposal(p)
}

// commit appends b to the log and, for a block this replica proposed, records
// its propose-to-commit latency. Rounds at or below b's can no longer commit
// a block of this replica's, so their stamps go too.
func (r *Replica) commit(b *diempb.Block) {
	var lat time.Duration
	if t, ok := r.proposed[b.GetRound()]; ok && b.GetAuthor() == r.id {
		lat = time.Since(t)
		for round := range r.proposed {
			if round <= b.GetRound() {
				delete(r.proposed, round)
			}
		}
	}
	r.mu.Lock()
	r.commits = append(r.commits, b)
	r.commands += uint64(len(b.GetPayload()))
	if lat > 0 {
		r.latencies = append(r.latencies, lat)
	}
	r.mu.Unlock()
}

// Run serves the transport, waits for every peer, then runs the consensus loop
// until ctx is done. Waiting for peers before the first round matters: a
// proposal multicast into a half-connected configuration is simply lost, and
// with no block-sync in DiemBFT 3 the replicas that missed it never get it
// back. Cancelling ctx is how a replica stops; the transport is shut down after
// the loop, never before.
func (r *Replica) Run(ctx context.Context) error {
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
func (r *Replica) stop() {
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
func (r *Replica) ID() uint32 { return r.id }

// Addr is the address the transport listens on.
func (r *Replica) Addr() string { return r.net.Addr() }

// Log is the committed blocks, in commit order. It is safe to call from any
// goroutine; the core's own state deliberately is not exposed, since it belongs
// to the loop goroutine alone.
func (r *Replica) Log() []*diempb.Block {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*diempb.Block(nil), r.commits...)
}

// Latencies is the propose-to-commit latency of each committed block this
// replica proposed, measured on its own clock.
func (r *Replica) Latencies() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.latencies)
}

// Commands is how many commands the committed blocks carried.
func (r *Replica) Commands() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.commands
}

// Counters is what the transport had to discard.
func (r *Replica) Counters() diemnet.Counters { return r.net.Counters() }

// DeclinedMissingAncestor is how many votes this replica withheld because it
// never saw a block's ancestry. DiemBFT 3 defines no way to fetch the missing
// block, so a replica that loses one proposal cannot vote on its descendants
// either; this is the number that says what that costs.
func (r *Replica) DeclinedMissingAncestor() uint64 { return r.declined.Load() }

// QueueHighWater is the deepest the inbound event queue has been, which is what
// says whether inbound backpressure was ever felt.
func (r *Replica) QueueHighWater() int { return r.loop.QueueHighWater() }

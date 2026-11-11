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

	"github.com/DanyGoT/diembft/crypto"
	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
)

const (
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

	RoundTimeout    time.Duration
	MaxRoundTimeout time.Duration

	// Measure configures the measurement taken from core start. Its Duration
	// bounds the run; 0 runs until ctx is done.
	Measure benchkit.Options

	// Server, if set, is the Gorums server to run on, as gorums.NewLocalServers
	// provides for a single-process cluster. Peers and Listen are then unused,
	// and Rejected is the counter of the diemnet.VerifyInterceptor on it.
	Server      *gorums.Server
	Rejected    *atomic.Uint64
	DialOptions []gorums.DialOption
}

// Replica is one DiemBFT replica: a protocol core and the Gorums transport
// underneath.
type Replica struct {
	id   uint32
	core *diem.Core
	net  *diemnet.Transport

	// mu serializes every call into the core: inbound messages, fetched
	// blocks and the round timer. Gorums runs one sender's handlers in order,
	// and mu serializes them across senders. It also guards commits, commands
	// and proposed, which the core writes through the ledger and the transport.
	mu       sync.Mutex
	commits  []*diempb.Block
	commands uint64

	// proposed is when this replica sent its proposal for each round it led and
	// has not yet seen committed.
	proposed map[uint64]time.Time

	measure benchkit.Options
	m       *benchkit.Measurement
	result  *benchkit.Result
}

// New wires a replica.
func New(cfg Config) *Replica {
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
	r := &Replica{id: cfg.ID, proposed: map[uint64]time.Time{}, measure: cfg.Measure}
	ledger := diem.NewMemLedger()
	ledger.OnCommit = r.commit

	r.net = diemnet.New(diemnet.Config{
		ID:          cfg.ID,
		Peers:       cfg.Peers,
		Listen:      cfg.Listen,
		Verifier:    diem.NewVerifier(signer, diem.QuorumSize(len(validators))),
		Server:      cfg.Server,
		Rejected:    cfg.Rejected,
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
		Lock:         &r.mu,
		Transactions: cfg.Transactions,
	})
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
// a block of this replica's, so their stamps go too. It runs inside a core
// call, so mu is already held.
func (r *Replica) commit(b *diempb.Block) {
	if t, ok := r.proposed[b.GetRound()]; ok && b.GetAuthor() == r.id {
		r.m.Stats.AddLatency(time.Since(t))
		for round := range r.proposed {
			if round <= b.GetRound() {
				delete(r.proposed, round)
			}
		}
	}
	r.commits = append(r.commits, b)
	r.commands += uint64(len(b.GetPayload()))
}

// Run serves the transport, waits for every peer, then runs consensus until
// ctx is done or Measure.Duration has passed. Waiting for peers before the
// first round matters: a proposal multicast into a half-connected
// configuration is simply lost, and the replicas that missed it must fetch it
// before they can vote again. mu is held until the core has started, so a
// message that arrives earlier waits for it. Cancelling ctx is how a replica
// stops; the transport is shut down before the core.
func (r *Replica) Run(ctx context.Context) error {
	r.mu.Lock()
	r.net.Start(r.core, &r.mu)
	if err := r.net.WaitForPeers(ctx); err != nil {
		r.mu.Unlock()
		r.net.Stop()
		return err
	}
	r.m = benchkit.StartMeasurement(r.measure)
	r.core.Start()
	r.mu.Unlock()

	if d := r.measure.Duration; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	<-ctx.Done()

	// A core call may be waiting for space in a full send queue with mu held,
	// and only the transport's Stop ends that wait. Gorums does not wait for
	// its handler goroutines on Stop, so a late message can still reach the
	// core, and a stopped core ignores it.
	r.net.Stop()
	r.mu.Lock()
	r.core.Stop()
	r.result = r.m.Finish()
	r.mu.Unlock()
	return ctx.Err()
}

// Result is the run's measurement: an op is a committed block this replica
// proposed, timed propose to commit on its own clock. Read it only after Run
// returns; it is nil if Run never reached the first round.
func (r *Replica) Result() *benchkit.Result { return r.result }

// ID is this replica's identity.
func (r *Replica) ID() uint32 { return r.id }

// Addr is the address the transport listens on.
func (r *Replica) Addr() string { return r.net.Addr() }

// Log is the committed blocks, in commit order. It is safe to call from any
// goroutine.
func (r *Replica) Log() []*diempb.Block {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*diempb.Block(nil), r.commits...)
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
// had not yet seen a block's ancestry. Until it has fetched the missing block,
// a replica that loses one proposal cannot vote on its descendants either; this
// is the number that says what that costs.
func (r *Replica) DeclinedMissingAncestor() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.core.State().DeclinedMissingAncestor
}

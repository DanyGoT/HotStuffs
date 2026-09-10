// Package simnet is a deterministic, single-goroutine N-replica harness for
// consensus: it implements hotstuff.Transport over an in-memory, seeded
// delivery schedule and one shared fake clock, converting each scheduled
// message into the same event and edge verification a real handler would use.
// It is the plug point for future Twins-style testing.
package simnet

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/consensus"
	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// defaultViewDuration is the base view timeout used when WithViewDuration is
// not given.
const defaultViewDuration = 100 * time.Millisecond

// runUntilKick is how many view durations RunUntil advances the clock by when
// the schedule runs dry, generous enough to fire any armed timer regardless of
// how far its backoff has grown.
const runUntilKick = 128

// config collects the options.
type config struct {
	seed     int64
	hasSeed  bool
	viewBase time.Duration
}

// Option configures a Net built by New.
type Option func(*config)

// WithSeed fixes the shuffle order of the message schedule, so a failing run
// reproduces from one number.
func WithSeed(seed int64) Option {
	return func(c *config) { c.seed, c.hasSeed = seed, true }
}

// WithViewDuration sets the base view timeout.
func WithViewDuration(d time.Duration) Option {
	return func(c *config) { c.viewBase = d }
}

// kind is the shape of one scheduled item.
type kind int

const (
	kProposal kind = iota
	kVote
	kTimeout
	kFetch
	kInject
)

func (k kind) String() string {
	switch k {
	case kProposal:
		return "propose"
	case kVote:
		return "vote"
	case kTimeout:
		return "timeout"
	case kInject:
		return "inject"
	default:
		return "fetch"
	}
}

// scheduled is one pending item on the Net's schedule: one recipient of a
// one-way message (event set, kind is kProposal/kVote/kTimeout/kInject), or a
// fetch request (hash set, kind is kFetch, to is -1). A broadcast becomes one
// item per recipient, so a seeded schedule interleaves recipients as well as
// messages. Reachability is evaluated at delivery, not here, so a Partition
// call between send and delivery still takes effect.
type scheduled struct {
	from  int
	to    int
	kind  kind
	event hotstuff.Event
	hash  hotstuff.Hash
}

// Delivery is one pending delivery as a Drop predicate sees it: Event, from
// replica From to replica To; or, with Event nil and To -1, the backfill
// request From issued for Hash, which has no single recipient.
type Delivery struct {
	From, To int
	Event    hotstuff.Event
	Hash     hotstuff.Hash
}

// replica is one node in the simulated network, addressed by index; its
// hotstuff.ID is a separate mapping, the one concession to future Twins.
type replica struct {
	id      hotstuff.ID
	core    *consensus.Core
	loop    *consensus.Loop
	store   *blockchain.Store
	log     *hotstuff.MemLog
	ver     *hotstuff.Verifier
	crashed bool
}

// Net is the deterministic N-replica harness.
type Net struct {
	t            testing.TB
	replicas     []*replica
	clock        *fake.Clock
	schedule     []scheduled
	rng          *rand.Rand
	partitions   [][]int
	drop         func(Delivery) bool
	trace        []string
	step         int
	viewDuration time.Duration
}

// transport is a replica's outbound half: every method appends to the Net's
// schedule instead of sending, tagged with the sending replica's index.
type transport struct {
	net  *Net
	from int
}

// broadcast schedules e for every replica, this one included.
func (rt *transport) broadcast(k kind, e hotstuff.Event) {
	for to := range rt.net.replicas {
		rt.net.schedule = append(rt.net.schedule, scheduled{from: rt.from, to: to, kind: k, event: e})
	}
}

func (rt *transport) Propose(p hotstuff.Proposal) {
	rt.broadcast(kProposal, hotstuff.ProposeEvent{Proposal: p})
}
func (rt *transport) Vote(c hotstuff.PartialCert) {
	rt.broadcast(kVote, hotstuff.VoteEvent{PartialCert: c})
}
func (rt *transport) Timeout(m hotstuff.TimeoutMsg) {
	rt.broadcast(kTimeout, hotstuff.TimeoutEvent{TimeoutMsg: m})
}
func (rt *transport) Fetch(h hotstuff.Hash) {
	rt.net.schedule = append(rt.net.schedule, scheduled{from: rt.from, to: -1, kind: kFetch, hash: h})
}

var _ hotstuff.Transport = (*transport)(nil)

// New builds an n-replica network sharing one fake clock, all started at
// view 1.
func New(t testing.TB, n int, opts ...Option) *Net {
	o := config{viewBase: defaultViewDuration}
	for _, opt := range opts {
		opt(&o)
	}

	nt := &Net{
		t:            t,
		clock:        fake.NewClock(time.Unix(0, 0)),
		viewDuration: o.viewBase,
	}
	if o.hasSeed {
		nt.rng = rand.New(rand.NewSource(o.seed))
	}

	leader := hotstuff.RoundRobin(n)
	for i := range n {
		id := hotstuff.ID(i + 1)
		store := blockchain.New()
		log := hotstuff.NewMemLog()
		signer := nocrypto.New(id, n)
		queue := hotstuff.NewQueue(4096)

		core := consensus.New(consensus.Config{
			ID:        id,
			N:         n,
			Rules:     consensus.NewRules(id, store),
			Store:     store,
			Crypto:    signer,
			Transport: &transport{net: nt, from: i},
			Leader:    leader,
			Clock:     nt.clock,
			Duration:  consensus.NewViewDuration(o.viewBase, 64*o.viewBase, 2),
			Commands:  &fake.Commands{},
			Executor:  log,
			Sink:      queue, // hotstuff.Queue.Push implements EventSink directly
		})

		nt.replicas = append(nt.replicas, &replica{
			id:    id,
			core:  core,
			loop:  consensus.NewLoop(core, queue),
			store: store,
			log:   log,
			ver:   hotstuff.NewVerifier(signer, leader),
		})
	}

	for _, r := range nt.replicas {
		r.core.Start()
	}
	nt.pumpAll()
	return nt
}

// Deliver pops and delivers up to n scheduled messages, returning how many it
// actually delivered. One broadcast counts once per recipient.
func (nt *Net) Deliver(n int) int {
	delivered := 0
	for ; delivered < n; delivered++ {
		m, ok := nt.pop()
		if !ok {
			break
		}
		nt.deliverOne(m)
	}
	return delivered
}

// RunUntil delivers messages until pred holds or maxSteps is spent, advancing
// the clock whenever the schedule runs dry. It reports whether pred held.
func (nt *Net) RunUntil(pred func() bool, maxSteps int) bool {
	for range maxSteps {
		if pred() {
			return true
		}
		if len(nt.schedule) == 0 {
			nt.Advance(runUntilKick * nt.viewDuration)
			continue
		}
		nt.Deliver(1)
	}
	return pred()
}

// Advance moves the shared clock forward, firing view timers.
func (nt *Net) Advance(d time.Duration) {
	nt.clock.Advance(d)
	nt.pumpAll()
}

// pumpAll ticks every live replica's loop to quiescence, so events pushed
// directly onto a queue (view timers) get processed.
func (nt *Net) pumpAll() {
	for _, r := range nt.replicas {
		if r.crashed {
			continue
		}
		for r.loop.Tick() {
		}
	}
}

// Crash stops replica idx: it sends nothing further and receives nothing.
func (nt *Net) Crash(idx int) {
	r := nt.replicas[idx]
	r.crashed = true
	r.core.Stop()
}

// Partition splits the replicas into groups that cannot reach each other,
// replacing any previous partitioning. An index named in no set stays
// reachable from everyone.
func (nt *Net) Partition(sets ...[]int) { nt.partitions = sets }

// Heal removes every partition.
func (nt *Net) Heal() { nt.partitions = nil }

// Drop installs a predicate consulted for every delivery; returning true
// discards that one. It is how a test says "replica 3 misses exactly this
// block", which Partition is far too blunt to express. A nil pred clears it.
func (nt *Net) Drop(pred func(Delivery) bool) { nt.drop = pred }

// Inject schedules e from replica "from" to replica "to" outside any replica's
// transport, which is the only way this harness produces a message an honest
// core would never send. Unlike scheduled traffic it is not asserted to
// verify: an injected message the receiver rejects is dropped, exactly as a
// real handler drops it.
func (nt *Net) Inject(from, to int, e hotstuff.Event) {
	nt.schedule = append(nt.schedule, scheduled{from: from, to: to, kind: kInject, event: e})
}

// Log is replica idx's committed blocks, in commit order.
func (nt *Net) Log(idx int) []*hotstuff.Block { return nt.replicas[idx].log.Snapshot() }

// CheckSafety asserts the safety invariants over every replica's commit log.
func (nt *Net) CheckSafety(t testing.TB) {
	logs := make(map[hotstuff.ID][]*hotstuff.Block, len(nt.replicas))
	for _, r := range nt.replicas {
		logs[r.id] = r.log.Snapshot()
	}
	CheckSafety(t, logs)
}

// Trace is the delivery trace, one line per delivered message, for the report.
func (nt *Net) Trace() []string { return append([]string(nil), nt.trace...) }

// ID is the hotstuff.ID of replica idx.
func (nt *Net) ID(idx int) hotstuff.ID { return nt.replicas[idx].id }

// N is the replica count.
func (nt *Net) N() int { return len(nt.replicas) }

// pop removes and returns one pending item: a uniformly random one, drawn from
// the Net's own *rand.Rand, when a seed was given; otherwise the oldest one.
// Either way the choice is a pure function of the seed and the run so far.
func (nt *Net) pop() (scheduled, bool) {
	if len(nt.schedule) == 0 {
		return scheduled{}, false
	}
	i := 0
	if nt.rng != nil {
		i = nt.rng.Intn(len(nt.schedule))
	}
	m := nt.schedule[i]
	nt.schedule = slices.Delete(nt.schedule, i, i+1)
	return m, true
}

// deliverOne delivers one scheduled item, skipping it entirely if its sender
// had since crashed or the Drop predicate rejects it.
func (nt *Net) deliverOne(m scheduled) {
	if nt.replicas[m.from].crashed {
		return
	}
	if nt.drop != nil && nt.drop(Delivery{From: m.from, To: m.to, Event: m.event, Hash: m.hash}) {
		return
	}
	if m.kind == kFetch {
		nt.deliverFetch(m.from, m.hash)
		return
	}
	nt.push(m)
}

// push delivers m's event, verifying at the edge exactly as a real handler
// would. A message this harness built must always verify, so a rejection there
// is a real bug rather than a scenario; an injected one is Byzantine by
// construction, and dropping it is what a real handler does.
func (nt *Net) push(m scheduled) {
	if !nt.reachable(m.from, m.to) {
		return
	}
	dst := nt.replicas[m.to]
	if !nt.verifyEvent(dst, m.event) {
		if m.kind != kInject {
			nt.t.Fatalf("replica %d rejected %s from replica %d", dst.id, m.kind, m.from+1)
		}
		return
	}
	dst.loop.Push(m.event)
	for dst.loop.Tick() {
	}
	nt.step++
	nt.trace = append(nt.trace, fmt.Sprintf("%d r%d->r%d %s view=%d", nt.step, m.from+1, m.to+1, m.kind, eventView(m.event)))
}

// deliverFetch answers a fetch by scanning replicas in index order for one
// that holds the block and is reachable from the requester. If none does, the
// fetch is simply dropped, exactly as a real one would time out. The block
// comes from a content-addressed lookup by the requested hash, so it needs no
// further verification.
func (nt *Net) deliverFetch(from int, h hotstuff.Hash) {
	for i, holder := range nt.replicas {
		if !nt.reachable(from, i) {
			continue
		}
		b, ok := holder.store.Get(h)
		if !ok {
			continue
		}
		dst := nt.replicas[from]
		dst.loop.Push(hotstuff.FetchedEvent{Block: b})
		for dst.loop.Tick() {
		}
		nt.step++
		nt.trace = append(nt.trace, fmt.Sprintf("%d r%d->r%d fetch hash=%x", nt.step, i+1, from+1, h[:4]))
		return
	}
}

// reachable reports whether a and b can reach each other: neither has
// crashed, and no partition set contains exactly one of them.
func (nt *Net) reachable(a, b int) bool {
	if nt.replicas[a].crashed || nt.replicas[b].crashed {
		return false
	}
	for _, set := range nt.partitions {
		if slices.Contains(set, a) != slices.Contains(set, b) {
			return false
		}
	}
	return true
}

// verifyEvent checks e with dst's own Verifier. A FetchedEvent needs no check
// here: deliverFetch answers by content-addressed lookup, and an injected one
// is a fault the test meant to deliver.
func (nt *Net) verifyEvent(dst *replica, e hotstuff.Event) bool {
	switch ev := e.(type) {
	case hotstuff.ProposeEvent:
		return dst.ver.VerifyProposal(ev.Proposal)
	case hotstuff.VoteEvent:
		return dst.ver.VerifyVote(ev.PartialCert)
	case hotstuff.TimeoutEvent:
		return dst.ver.VerifyTimeout(ev.TimeoutMsg)
	default:
		return true
	}
}

// eventView is the view a trace line reports for e.
func eventView(e hotstuff.Event) hotstuff.View {
	switch ev := e.(type) {
	case hotstuff.ProposeEvent:
		return ev.Block.View()
	case hotstuff.VoteEvent:
		return ev.View
	case hotstuff.TimeoutEvent:
		return ev.View
	default:
		return 0
	}
}

package diem

import (
	"context"
	"sync/atomic"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// Queue is the inbound queue for the consensus goroutine: bounded and
// blocking, so a producer waits rather than an accepted input being dropped.
// An input is a verified *diempb message, a fetched *diempb.Block, or a
// func(*Core) for anything that is not a message.
type Queue chan any

// NewQueue returns a queue of the given capacity.
func NewQueue(size int) Queue { return make(Queue, size) }

// Push blocks when the queue is full. It never drops.
func (q Queue) Push(m any) { q <- m }

// dispatch hands m to the Core method for its type. It is the paper's
// start_event_processing (3.1).
func dispatch(c *Core, m any) {
	switch m := m.(type) {
	case *diempb.ProposalMsg:
		c.OnProposal(m)
	case *diempb.VoteMsg:
		c.OnVote(m)
	case *diempb.TimeoutMsg:
		c.OnTimeout(m)
	case *diempb.Block:
		c.OnBlock(m)
	case func(*Core):
		m(c)
	}
}

// Loop drives a Core from its queue. The core is drivable at three levels, and
// that is the whole testability story: its methods for state-machine unit
// tests, Tick for the deterministic harness, Run in production.
type Loop struct {
	core *Core
	q    Queue
	high atomic.Int64
}

// NewLoop pairs a core with the queue it was constructed against.
func NewLoop(c *Core, q Queue) *Loop { return &Loop{core: c, q: q} }

// step records how deep the queue was, then dispatches m. The high-water mark
// is written only from this goroutine and read from any, which is all the
// atomic is for.
func (l *Loop) step(m any) {
	if n := int64(len(l.q)); n > l.high.Load() {
		l.high.Store(n)
	}
	dispatch(l.core, m)
	if l.core.observe != nil {
		l.core.observe(l.core.State())
	}
}

// QueueHighWater is the deepest the inbound queue has been seen: the number
// that says whether inbound backpressure was ever felt.
func (l *Loop) QueueHighWater() int { return int(l.high.Load()) }

// Push enqueues from any goroutine, blocking when the queue is full. Inbound
// backpressure is deliberate: dropping an already-accepted input is worse than
// making its producer wait.
func (l *Loop) Push(m any) { l.q.Push(m) }

// Tick processes exactly one queued input, reporting false if there was none.
func (l *Loop) Tick() bool {
	select {
	case m := <-l.q:
		l.step(m)
		return true
	default:
		return false
	}
}

// Run processes the queue until ctx is done. The caller starts the core, so
// that a replica can wait for its peers first.
func (l *Loop) Run(ctx context.Context) error {
	defer l.core.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m := <-l.q:
			l.step(m)
		}
	}
}

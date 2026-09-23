package diem

import (
	"context"
	"sync/atomic"
)

// Loop drives a Core from its queue. The core is drivable at three levels, and
// that is the whole testability story: Core.Step for state-machine unit tests,
// Tick for the deterministic harness, Run in production.
type Loop struct {
	core *Core
	q    Queue
	high atomic.Int64
}

// NewLoop pairs a core with the queue it was constructed against.
func NewLoop(c *Core, q Queue) *Loop { return &Loop{core: c, q: q} }

// step records how deep the queue was, then runs the event. The high-water
// mark is written only from this goroutine and read from any, which is all the
// atomic is for.
func (l *Loop) step(e Event) {
	if n := int64(len(l.q)); n > l.high.Load() {
		l.high.Store(n)
	}
	l.core.Step(e)
}

// QueueHighWater is the deepest the inbound queue has been seen: the number
// that says whether inbound backpressure was ever felt.
func (l *Loop) QueueHighWater() int { return int(l.high.Load()) }

// Push enqueues an event from any goroutine, blocking when the queue is full.
// Inbound backpressure is deliberate: dropping an already-accepted event is
// worse than making its producer wait.
func (l *Loop) Push(e Event) { l.q.Push(e) }

// Tick processes exactly one queued event, reporting false if there was none.
func (l *Loop) Tick() bool {
	select {
	case e := <-l.q:
		l.step(e)
		return true
	default:
		return false
	}
}

// Run processes events until ctx is done. The caller starts the core, so that a
// replica can wait for its peers first.
func (l *Loop) Run(ctx context.Context) error {
	defer l.core.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-l.q:
			l.step(e)
		}
	}
}

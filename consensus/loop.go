package consensus

import (
	"context"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Loop drives a Core from its queue. The core is drivable at three levels, and
// that is the whole testability story: Core.Step for state-machine unit tests,
// Tick for the deterministic harness, Run in production.
type Loop struct {
	core *Core
	q    hotstuff.Queue
}

// NewLoop pairs a core with the queue it was constructed against.
func NewLoop(c *Core, q hotstuff.Queue) *Loop { return &Loop{core: c, q: q} }

// Push enqueues an event from any goroutine, blocking when the queue is full.
// Inbound backpressure is deliberate: dropping an already-accepted event is
// worse than making its producer wait.
func (l *Loop) Push(e hotstuff.Event) { l.q.Push(e) }

// Tick processes exactly one queued event, reporting false if there was none.
func (l *Loop) Tick() bool {
	select {
	case e := <-l.q:
		l.core.Step(e)
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
			l.core.Step(e)
		}
	}
}

var _ hotstuff.EventSink = (*Loop)(nil)

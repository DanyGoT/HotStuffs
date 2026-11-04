package diem

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newLoopFixture is replica 1 of 4 driven through its own queue, so the sink
// the round timer writes to is the queue the loop reads from.
func newLoopFixture(t *testing.T, observe func(State)) (*Loop, *recordNet) {
	t.Helper()
	q := NewQueue(8)
	net := &recordNet{}
	core := New(Config{
		ID:         1,
		Validators: []uint32{1, 2, 3, 4},
		Ledger:     NewMemLedger(),
		Crypto:     newTestSigner(testN),
		Transport:  net,
		Clock:      newFakeClock(),
		Backoff:    NewBackoff(100*time.Millisecond, time.Second, 2),
		Sink:       q.Push,
		Observer:   observe,
	})
	return NewLoop(core, q), net
}

func TestLoopTickProcessesOneInput(t *testing.T) {
	l, _ := newLoopFixture(t, nil)

	if l.Tick() {
		t.Fatal("Tick() = true on an empty queue")
	}
	var ran []int
	for i := range 3 {
		l.Push(func(*Core) { ran = append(ran, i) })
	}

	for i := range 3 {
		if !l.Tick() {
			t.Fatalf("Tick() = false with %d inputs still queued", 3-i)
		}
		if len(ran) != i+1 || ran[i] != i {
			t.Fatalf("after %d ticks ran %v, want the first %d in order", i+1, ran, i+1)
		}
	}
	// step reads the queue after taking its input, so the deepest it ever saw
	// was the two left behind the first one.
	if got := l.QueueHighWater(); got != 2 {
		t.Errorf("QueueHighWater() = %d, want 2", got)
	}
	if l.Tick() {
		t.Error("Tick() = true on a drained queue")
	}
}

// TestLoopRunProcessesThenStops covers both arms of Run's select without a
// goroutine: the observer cancels the context once the queued input has run,
// so the next pass takes the ctx.Done arm.
func TestLoopRunProcessesThenStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l, net := newLoopFixture(t, func(State) { cancel() })
	l.core.Start()
	l.Push(func(c *Core) { c.pacemaker.LocalTimeoutRound() })

	if err := l.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context.Canceled", err)
	}
	if len(net.timeouts) != 1 {
		t.Errorf("Run processed %d timeouts, want 1", len(net.timeouts))
	}
}

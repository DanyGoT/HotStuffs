package diem

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/internal/fake"
)

// newLoopFixture is replica 1 of 4 driven through its own queue, so the sink
// the round timer writes to is the queue the loop reads from.
func newLoopFixture(t *testing.T, observe func(Event, State, time.Duration)) (*Loop, *recordNet) {
	t.Helper()
	q := NewQueue(8)
	net := &recordNet{}
	core := New(Config{
		ID:         1,
		Validators: []ID{1, 2, 3, 4},
		Ledger:     NewMemLedger(),
		Crypto:     nocrypto.New(1, testN),
		Transport:  net,
		Clock:      fake.NewClock(time.Unix(0, 0)),
		Duration:   hotstuff.NewDuration(100*time.Millisecond, time.Second, 2),
		Sink:       q.Push,
		Observer:   observe,
	})
	return NewLoop(core, q), net
}

func TestLoopTickProcessesOneEvent(t *testing.T) {
	l, net := newLoopFixture(t, nil)
	l.core.Start()

	if l.Tick() {
		t.Fatal("Tick() = true on an empty queue")
	}
	// Two events Core drops as stale, then the one it acts on.
	l.Push(LocalTimeoutEvent{Round: 0})
	l.Push(LocalTimeoutEvent{Round: 0})
	l.Push(LocalTimeoutEvent{Round: 1})

	for i := range 2 {
		if !l.Tick() {
			t.Fatalf("Tick() = false with %d events still queued", 3-i)
		}
		if len(net.timeouts) != 0 {
			t.Fatalf("a stale timer event produced %d timeouts, want 0", len(net.timeouts))
		}
	}
	// step reads the queue after taking its event, so the deepest it ever saw
	// was the two left behind the first one.
	if got := l.QueueHighWater(); got != 2 {
		t.Errorf("QueueHighWater() = %d, want 2", got)
	}
	if !l.Tick() || len(net.timeouts) != 1 {
		t.Fatalf("the current-round timer event produced %d timeouts, want 1", len(net.timeouts))
	}
	if l.Tick() {
		t.Error("Tick() = true on a drained queue")
	}
}

// TestLoopRunProcessesThenStops covers both arms of Run's select without a
// goroutine: the observer cancels the context once the queued event has been
// stepped, so the next pass takes the ctx.Done arm.
func TestLoopRunProcessesThenStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l, net := newLoopFixture(t, func(Event, State, time.Duration) { cancel() })
	l.core.Start()
	l.Push(LocalTimeoutEvent{Round: 1})

	if err := l.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context.Canceled", err)
	}
	if len(net.timeouts) != 1 {
		t.Errorf("Run processed %d timer events, want 1", len(net.timeouts))
	}
}

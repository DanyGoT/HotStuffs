package replica

import (
	"bytes"
	"testing"
	"time"
)

func TestPayloadUnthrottled(t *testing.T) {
	const size, batch = 32, 4
	p := NewPayload(size, batch, 0)
	for i := range 5 {
		cmds := p.Transactions()
		if len(cmds) != batch {
			t.Fatalf("call %d: len(cmds) = %d, want %d", i, len(cmds), batch)
		}
		for _, c := range cmds {
			if len(c) != size {
				t.Errorf("call %d: command length = %d, want %d", i, len(c), size)
			}
		}
	}
}

func TestPayloadClampsSizeAndBatch(t *testing.T) {
	p := NewPayload(0, 0, 0)
	cmds := p.Transactions()
	if len(cmds) != 1 {
		t.Fatalf("len(cmds) = %d, want 1", len(cmds))
	}
	if len(cmds[0]) != 1 {
		t.Fatalf("command length = %d, want 1", len(cmds[0]))
	}
}

// TestPayloadThrottled bounds how much a throttled Payload can hand out over a
// measured interval. Only an upper bound is checked: a lower bound would tie
// the assertion to scheduler timing, which is exactly how this test would
// flake.
func TestPayloadThrottled(t *testing.T) {
	const rate = 200 // commands/sec
	p := NewPayload(8, 1000, rate)

	start := time.Now()
	deadline := start.Add(150 * time.Millisecond)
	total := 0
	for time.Now().Before(deadline) {
		total += len(p.Transactions())
	}
	elapsed := time.Since(start)

	// +2 covers int() truncation of the credit and the gap between the last
	// call and the elapsed measurement.
	max := int(elapsed.Seconds()*rate) + 2
	if total > max {
		t.Errorf("throttled Transactions handed out %d commands over %v at rate %d/s, want <= %d", total, elapsed, rate, max)
	}
}

// TestPayloadCommandsAreUniform checks that every command in one batch shares
// the same length and content, by value rather than pointer identity.
func TestPayloadCommandsAreUniform(t *testing.T) {
	p := NewPayload(16, 5, 0)
	cmds := p.Transactions()
	for i, c := range cmds {
		if len(c) != len(cmds[0]) {
			t.Errorf("command %d: length = %d, want %d", i, len(c), len(cmds[0]))
		}
		if !bytes.Equal(c, cmds[0]) {
			t.Errorf("command %d: content differs from command 0", i)
		}
	}
}

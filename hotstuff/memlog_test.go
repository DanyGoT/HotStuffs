package hotstuff

import "testing"

func TestMemLog(t *testing.T) {
	l := NewMemLog()
	b1 := NewBlock(GenesisHash(), 1, 1, QuorumCert{}, nil)
	b2 := NewBlock(b1.Hash(), 2, 1, QuorumCert{}, nil)
	b3 := NewBlock(b2.Hash(), 3, 1, QuorumCert{}, nil)

	if l.Len() != 0 {
		t.Fatalf("Len() = %d before any Exec, want 0", l.Len())
	}

	l.Exec(b1)
	l.Exec(b2)
	l.Exec(b3)

	if got := l.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	snap := l.Snapshot()
	want := []*Block{b1, b2, b3}
	if len(snap) != len(want) {
		t.Fatalf("Snapshot() has %d blocks, want %d", len(snap), len(want))
	}
	for i := range want {
		if snap[i] != want[i] {
			t.Errorf("Snapshot()[%d] = %v, want %v", i, snap[i], want[i])
		}
	}

	// Mutating the returned slice must not affect a later snapshot.
	snap[0] = b3
	snap2 := l.Snapshot()
	if snap2[0] != b1 {
		t.Errorf("Snapshot() after mutating a prior snapshot: [0] = %v, want %v (Snapshot must copy)", snap2[0], b1)
	}
}

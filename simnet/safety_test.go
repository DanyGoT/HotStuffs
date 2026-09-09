package simnet

import (
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// chain builds blocks for the given views, each extending the previous and
// carrying a QC for it, rooted at genesis.
func chain(views ...hotstuff.View) []*hotstuff.Block {
	blocks := make([]*hotstuff.Block, len(views))
	parent := hotstuff.Genesis()
	for i, v := range views {
		qc := hotstuff.QuorumCert{View: parent.View(), BlockHash: parent.Hash()}
		blocks[i] = hotstuff.NewBlock(parent.Hash(), v, 1, qc, nil)
		parent = blocks[i]
	}
	return blocks
}

func TestSafetyErrorsAcceptsGoodLogs(t *testing.T) {
	t.Run("identical logs", func(t *testing.T) {
		log := chain(1, 2, 3)
		logs := map[hotstuff.ID][]*hotstuff.Block{1: log, 2: log}
		if errs := SafetyErrors(logs); len(errs) != 0 {
			t.Errorf("SafetyErrors() = %v, want none", errs)
		}
	})

	t.Run("short log is a prefix of a longer one", func(t *testing.T) {
		long := chain(1, 2, 3, 4, 5)
		logs := map[hotstuff.ID][]*hotstuff.Block{1: long[:2], 2: long}
		if errs := SafetyErrors(logs); len(errs) != 0 {
			t.Errorf("SafetyErrors() = %v, want none", errs)
		}
	})

	t.Run("empty map", func(t *testing.T) {
		if errs := SafetyErrors(nil); len(errs) != 0 {
			t.Errorf("SafetyErrors(nil) = %v, want none", errs)
		}
	})
}

// TestSafetyErrorsCatchesEachViolation exercises every rule SafetyErrors
// claims to check, one violation at a time. An oracle that never fires is
// worthless, so this is what makes the seeded sweep mean anything.
func TestSafetyErrorsCatchesEachViolation(t *testing.T) {
	t.Run("log[0] parent is not genesis", func(t *testing.T) {
		b := hotstuff.NewBlock(hotstuff.Hash{0x99}, 1, 1, hotstuff.QuorumCert{}, nil)
		logs := map[hotstuff.ID][]*hotstuff.Block{1: {b}}
		if errs := SafetyErrors(logs); len(errs) == 0 {
			t.Error("SafetyErrors() = none, want a violation")
		}
	})

	t.Run("broken parent link mid-log", func(t *testing.T) {
		good := chain(1, 2)
		broken := hotstuff.NewBlock(hotstuff.Hash{0x77}, 3, 1, hotstuff.QuorumCert{View: 2, BlockHash: good[1].Hash()}, nil)
		logs := map[hotstuff.ID][]*hotstuff.Block{1: {good[0], good[1], broken}}
		if errs := SafetyErrors(logs); len(errs) == 0 {
			t.Error("SafetyErrors() = none, want a violation")
		}
	})

	t.Run("view does not increase", func(t *testing.T) {
		b1 := chain(1)[0]
		b2 := hotstuff.NewBlock(b1.Hash(), 1, 1, hotstuff.QuorumCert{View: 1, BlockHash: b1.Hash()}, nil)
		logs := map[hotstuff.ID][]*hotstuff.Block{1: {b1, b2}}
		if errs := SafetyErrors(logs); len(errs) == 0 {
			t.Error("SafetyErrors() = none, want a violation")
		}
	})

	t.Run("two replicas commit different blocks at the same index", func(t *testing.T) {
		a := chain(1, 2)
		b1 := a[0]
		other := hotstuff.NewBlock(hotstuff.GenesisHash(), 1, 2, hotstuff.QuorumCert{}, [][]byte{[]byte("fork")})
		logs := map[hotstuff.ID][]*hotstuff.Block{1: {b1}, 2: {other}}
		if errs := SafetyErrors(logs); len(errs) == 0 {
			t.Error("SafetyErrors() = none, want a violation")
		}
	})
}

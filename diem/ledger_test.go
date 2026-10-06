package diem

import (
	"bytes"
	"slices"
	"testing"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

func TestNewMemLedgerGenesisCommitted(t *testing.T) {
	l := NewMemLedger()

	if _, ok := l.CommittedBlock(genesisBlock.GetId()); !ok {
		t.Fatal("genesis is not committed")
	}
	state, ok := l.PendingState(genesisBlock.GetId())
	if !ok {
		t.Fatal("no commit state for genesis")
	}
	// A zero state id is the paper's bottom; genesis must not be mistaken for
	// "nothing committed yet".
	if bytes.Equal(state, zeroHash[:]) {
		t.Fatal("genesis commit state is zero, indistinguishable from the paper's bottom")
	}
}

func TestSpeculateOverKnownParentStoresState(t *testing.T) {
	l := NewMemLedger()
	b := NewBlock(1, 1, [][]byte{{0x01}}, bareQC(genesisBlock.GetId(), 0))

	state := l.Speculate(b)
	if bytes.Equal(state, zeroHash[:]) {
		t.Fatal("Speculate returned the zero state over a known parent")
	}
	got, ok := l.PendingState(b.GetId())
	if !ok || !bytes.Equal(got, state) {
		t.Fatalf("PendingState(b) = (%x, %v), want (%x, true)", got, ok, state)
	}
}

func TestSpeculateOverUnknownParentStoresNothing(t *testing.T) {
	l := NewMemLedger()
	b := NewBlock(1, 1, nil, bareQC(hashOf(0xFF), 0))

	if state := l.Speculate(b); !bytes.Equal(state, zeroHash[:]) {
		t.Fatalf("Speculate over an unknown parent = %x, want zero", state)
	}
	if _, ok := l.PendingState(b.GetId()); ok {
		t.Fatal("Speculate over an unknown parent stored a state anyway")
	}
}

func TestPendingStateAnswersForCommittedAndPendingBlocks(t *testing.T) {
	l := NewMemLedger()

	if _, ok := l.PendingState(genesisBlock.GetId()); !ok {
		t.Fatal("PendingState does not answer for the last committed block")
	}

	b := NewBlock(1, 1, nil, bareQC(genesisBlock.GetId(), 0))
	state := l.Speculate(b)
	if got, ok := l.PendingState(b.GetId()); !ok || !bytes.Equal(got, state) {
		t.Fatalf("PendingState(pending block) = (%x, %v), want (%x, true)", got, ok, state)
	}
}

func TestCommitFrontierIsNoop(t *testing.T) {
	l := NewMemLedger()
	before := l.commitID

	l.Commit([]byte(before))

	if l.commitID != before {
		t.Fatalf("Commit(frontier) moved the frontier from %x to %x", before, l.commitID)
	}
}

func TestCommitNonDescendantDoesNothing(t *testing.T) {
	l := NewMemLedger()
	before := l.commitID

	// Never speculated, so it cannot be a descendant of the frontier.
	stray := NewBlock(1, 1, nil, bareQC(hashOf(0xAB), 0))
	l.Commit(stray.GetId())

	if l.commitID != before {
		t.Fatalf("Commit(non-descendant) moved the frontier from %x to %x", before, l.commitID)
	}
	if _, ok := l.CommittedBlock(stray.GetId()); ok {
		t.Fatal("a non-descendant block was committed")
	}
}

func TestCommitAdvancesOverPrefixAndFiresOnCommitInOrder(t *testing.T) {
	l := NewMemLedger()
	var committed [][]byte
	l.OnCommit = func(b *diempb.Block) { committed = append(committed, b.GetId()) }

	b1 := NewBlock(1, 1, nil, bareQC(genesisBlock.GetId(), 0))
	l.Speculate(b1)
	b2 := NewBlock(1, 2, nil, bareQC(b1.GetId(), 1))
	l.Speculate(b2)
	b3 := NewBlock(1, 3, nil, bareQC(b2.GetId(), 2))
	l.Speculate(b3)

	l.Commit(b3.GetId())

	want := [][]byte{b1.GetId(), b2.GetId(), b3.GetId()}
	if !slices.EqualFunc(committed, want, bytes.Equal) {
		t.Fatalf("OnCommit fired for %x, want %x (oldest first)", committed, want)
	}
	for _, id := range want {
		if _, ok := l.CommittedBlock(id); !ok {
			t.Fatalf("block %x not committed", id)
		}
	}
}

func TestCommitPrunesConflictingForks(t *testing.T) {
	l := NewMemLedger()
	qc0 := bareQC(genesisBlock.GetId(), 0)
	forkA := NewBlock(1, 1, [][]byte{{0xA}}, qc0)
	forkB := NewBlock(1, 1, [][]byte{{0xB}}, qc0)
	l.Speculate(forkA)
	l.Speculate(forkB)

	l.Commit(forkA.GetId())

	if _, ok := l.CommittedBlock(forkA.GetId()); !ok {
		t.Fatal("the committed branch did not survive")
	}
	if _, ok := l.PendingState(forkB.GetId()); ok {
		t.Fatal("the conflicting branch survived Commit")
	}
}

func TestHistoryBoundsRetentionButKeepsFrontier(t *testing.T) {
	l := NewMemLedger()
	l.History = 1

	parent, parentRound := genesisBlock.GetId(), uint64(0)
	var blocks []*diempb.Block
	for i := uint64(1); i <= 3; i++ {
		b := NewBlock(1, i, nil, bareQC(parent, parentRound))
		l.Speculate(b)
		l.Commit(b.GetId())
		blocks = append(blocks, b)
		parent, parentRound = b.GetId(), i
	}

	if _, ok := l.CommittedBlock(genesisBlock.GetId()); ok {
		t.Fatal("genesis survived past the history bound")
	}
	if _, ok := l.CommittedBlock(blocks[0].GetId()); ok {
		t.Fatal("the oldest commit survived past the history bound")
	}
	last := blocks[len(blocks)-1]
	if _, ok := l.CommittedBlock(last.GetId()); !ok {
		t.Fatal("the current frontier was forgotten")
	}
}

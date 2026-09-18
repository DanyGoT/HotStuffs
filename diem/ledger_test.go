package diem

import (
	"slices"
	"testing"
)

// qcOver is a bare QC naming the parent a speculated block extends. Only
// VoteInfo.ID and VoteInfo.Round matter to MemLedger, so the rest of the QC is
// left zero.
func qcOver(id Hash, round Round) *QC {
	return &QC{VoteInfo: VoteInfo{ID: id, Round: round}}
}

func TestNewMemLedgerGenesisCommitted(t *testing.T) {
	l := NewMemLedger()

	if _, ok := l.CommittedBlock(genesisBlock.ID()); !ok {
		t.Fatal("genesis is not committed")
	}
	state, ok := l.PendingState(genesisBlock.ID())
	if !ok {
		t.Fatal("no commit state for genesis")
	}
	// A zero state id is the paper's bottom; genesis must not be mistaken for
	// "nothing committed yet".
	if state == (Hash{}) {
		t.Fatal("genesis commit state is zero, indistinguishable from the paper's bottom")
	}
}

func TestSpeculateOverKnownParentStoresState(t *testing.T) {
	l := NewMemLedger()
	b := NewBlock(1, 1, [][]byte{{0x01}}, qcOver(genesisBlock.ID(), 0))

	state := l.Speculate(b)
	if state == (Hash{}) {
		t.Fatal("Speculate returned the zero state over a known parent")
	}
	got, ok := l.PendingState(b.ID())
	if !ok || got != state {
		t.Fatalf("PendingState(b) = (%x, %v), want (%x, true)", got, ok, state)
	}
}

func TestSpeculateOverUnknownParentStoresNothing(t *testing.T) {
	l := NewMemLedger()
	b := NewBlock(1, 1, nil, qcOver(Hash{0xFF}, 0))

	if state := l.Speculate(b); state != (Hash{}) {
		t.Fatalf("Speculate over an unknown parent = %x, want zero", state)
	}
	if _, ok := l.PendingState(b.ID()); ok {
		t.Fatal("Speculate over an unknown parent stored a state anyway")
	}
}

func TestPendingStateAnswersForCommittedAndPendingBlocks(t *testing.T) {
	l := NewMemLedger()

	if _, ok := l.PendingState(genesisBlock.ID()); !ok {
		t.Fatal("PendingState does not answer for the last committed block")
	}

	b := NewBlock(1, 1, nil, qcOver(genesisBlock.ID(), 0))
	state := l.Speculate(b)
	if got, ok := l.PendingState(b.ID()); !ok || got != state {
		t.Fatalf("PendingState(pending block) = (%x, %v), want (%x, true)", got, ok, state)
	}
}

func TestCommitFrontierIsNoop(t *testing.T) {
	l := NewMemLedger()
	before := l.commitID

	l.Commit(before)

	if l.commitID != before {
		t.Fatalf("Commit(frontier) moved the frontier from %x to %x", before, l.commitID)
	}
}

func TestCommitNonDescendantDoesNothing(t *testing.T) {
	l := NewMemLedger()
	before := l.commitID

	// Never speculated, so it cannot be a descendant of the frontier.
	stray := NewBlock(1, 1, nil, qcOver(Hash{0xAB}, 0))
	l.Commit(stray.ID())

	if l.commitID != before {
		t.Fatalf("Commit(non-descendant) moved the frontier from %x to %x", before, l.commitID)
	}
	if _, ok := l.CommittedBlock(stray.ID()); ok {
		t.Fatal("a non-descendant block was committed")
	}
}

func TestCommitAdvancesOverPrefixAndFiresOnCommitInOrder(t *testing.T) {
	l := NewMemLedger()
	var committed []Hash
	l.OnCommit = func(b *Block) { committed = append(committed, b.ID()) }

	b1 := NewBlock(1, 1, nil, qcOver(genesisBlock.ID(), 0))
	l.Speculate(b1)
	b2 := NewBlock(1, 2, nil, qcOver(b1.ID(), 1))
	l.Speculate(b2)
	b3 := NewBlock(1, 3, nil, qcOver(b2.ID(), 2))
	l.Speculate(b3)

	l.Commit(b3.ID())

	want := []Hash{b1.ID(), b2.ID(), b3.ID()}
	if !slices.Equal(committed, want) {
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
	qc0 := qcOver(genesisBlock.ID(), 0)
	forkA := NewBlock(1, 1, [][]byte{{0xA}}, qc0)
	forkB := NewBlock(1, 1, [][]byte{{0xB}}, qc0)
	l.Speculate(forkA)
	l.Speculate(forkB)

	l.Commit(forkA.ID())

	if _, ok := l.CommittedBlock(forkA.ID()); !ok {
		t.Fatal("the committed branch did not survive")
	}
	if _, ok := l.PendingState(forkB.ID()); ok {
		t.Fatal("the conflicting branch survived Commit")
	}
}

func TestHistoryBoundsRetentionButKeepsFrontier(t *testing.T) {
	l := NewMemLedger()
	l.History = 1

	parent, parentRound := genesisBlock.ID(), Round(0)
	var blocks []*Block
	for i := Round(1); i <= 3; i++ {
		b := NewBlock(1, i, nil, qcOver(parent, parentRound))
		l.Speculate(b)
		l.Commit(b.ID())
		blocks = append(blocks, b)
		parent, parentRound = b.ID(), i
	}

	if _, ok := l.CommittedBlock(genesisBlock.ID()); ok {
		t.Fatal("genesis survived past the history bound")
	}
	if _, ok := l.CommittedBlock(blocks[0].ID()); ok {
		t.Fatal("the oldest commit survived past the history bound")
	}
	last := blocks[len(blocks)-1]
	if _, ok := l.CommittedBlock(last.ID()); !ok {
		t.Fatal("the current frontier was forgotten")
	}
}

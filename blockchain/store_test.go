package blockchain

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// extend builds n view-consecutive blocks extending parent, each carrying tag
// as its sole command so sibling forks differ.
func extend(parent *hotstuff.Block, n int, tag string) []*hotstuff.Block {
	blocks := make([]*hotstuff.Block, n)
	p := parent
	for i := range n {
		qc := hotstuff.QuorumCert{View: p.View(), BlockHash: p.Hash()}
		p = hotstuff.NewBlock(p.Hash(), p.View()+1, 1, qc, [][]byte{[]byte(tag)})
		blocks[i] = p
	}
	return blocks
}

// chain builds view-consecutive blocks 1..n rooted at genesis, each extending
// the previous, with tag mixed into the commands so sibling forks differ.
func chain(n int, tag string) []*hotstuff.Block {
	return extend(hotstuff.Genesis(), n, tag)
}

func TestNewHoldsGenesis(t *testing.T) {
	s := New()

	b, ok := s.Get(hotstuff.GenesisHash())
	if !ok {
		t.Fatal("Get(GenesisHash()) = false, want true")
	}
	if b != hotstuff.Genesis() {
		t.Error("Get(GenesisHash()) returned a different pointer than Genesis()")
	}
	if s.Len() != 1 {
		t.Errorf("Len() = %d, want 1", s.Len())
	}
}

func TestGetPut(t *testing.T) {
	s := New()
	b1 := chain(1, "a")[0]

	if _, ok := s.Get(b1.Hash()); ok {
		t.Fatal("Get on unstored hash = true, want false")
	}

	s.Put(b1)
	got, ok := s.Get(b1.Hash())
	if !ok || got != b1 {
		t.Fatalf("Get after Put = (%v, %v), want (%p, true)", got, ok, b1)
	}

	lenAfterFirstPut := s.Len()
	s.Put(b1)
	if s.Len() != lenAfterFirstPut {
		t.Errorf("Len() after re-Put of same block = %d, want %d", s.Len(), lenAfterFirstPut)
	}

	// Same fields, freshly built: identical hash, distinct pointer.
	dup := hotstuff.NewBlock(b1.Parent(), b1.View(), b1.Proposer(), b1.QC(), b1.Cmds())
	if dup.Hash() != b1.Hash() {
		t.Fatal("dup built from identical fields hashes differently than b1")
	}
	if dup == b1 {
		t.Fatal("dup is the same pointer as b1; test built no fresh block")
	}

	s.Put(dup)
	if s.Len() != lenAfterFirstPut {
		t.Errorf("Len() after Put of equal-content block = %d, want %d", s.Len(), lenAfterFirstPut)
	}
	got, _ = s.Get(b1.Hash())
	if got != b1 {
		t.Error("Put of equal-content block replaced the stored pointer")
	}
}

func TestPruneKeepsAncestors(t *testing.T) {
	s := New()
	main := chain(4, "main")
	for _, b := range main {
		s.Put(b)
	}
	b1, b2, b3, b4 := main[0], main[1], main[2], main[3]

	dropped := s.Prune(b3.Hash())

	if len(dropped) != 0 {
		t.Errorf("Prune returned %d blocks, want 0: %v", len(dropped), dropped)
	}
	for name, h := range map[string]hotstuff.Hash{
		"genesis": hotstuff.GenesisHash(),
		"b1":      b1.Hash(),
		"b2":      b2.Hash(),
		"b3":      b3.Hash(),
		"b4":      b4.Hash(),
	} {
		if _, ok := s.Get(h); !ok {
			t.Errorf("%s missing after Prune", name)
		}
	}
}

func TestPruneDropsForks(t *testing.T) {
	s := New()
	main := chain(4, "main")
	for _, b := range main {
		s.Put(b)
	}
	b1, b3 := main[0], main[2]

	fork := extend(b1, 2, "fork")
	for _, b := range fork {
		s.Put(b)
	}
	f2, f3 := fork[0], fork[1]

	dropped := s.Prune(b3.Hash())

	if len(dropped) != 2 || dropped[0] != f3 || dropped[1] != f2 {
		t.Fatalf("Prune returned %v, want [f3, f2]", dropped)
	}
	if _, ok := s.Get(f2.Hash()); ok {
		t.Error("f2 still present after Prune")
	}
	if _, ok := s.Get(f3.Hash()); ok {
		t.Error("f3 still present after Prune")
	}
	if _, ok := s.Get(hotstuff.GenesisHash()); !ok {
		t.Error("genesis missing after Prune")
	}
	for i, b := range main {
		if _, ok := s.Get(b.Hash()); !ok {
			t.Errorf("main[%d] missing after Prune", i)
		}
	}
}

func TestPruneAboveHeadViewSurvives(t *testing.T) {
	s := New()
	main := chain(4, "main")
	for _, b := range main {
		s.Put(b)
	}
	b1, b3, b4 := main[0], main[2], main[3]

	fork := extend(b1, 4, "fork") // f2..f5; f5 is above b3's view
	for _, b := range fork {
		s.Put(b)
	}
	above := fork[3] // view 5 > b3's view 3

	dropped := s.Prune(b3.Hash())

	for _, d := range dropped {
		if d == above {
			t.Fatal("block above head's view was returned by Prune")
		}
	}
	if _, ok := s.Get(above.Hash()); !ok {
		t.Error("block above head's view was deleted by Prune")
	}
	if _, ok := s.Get(b4.Hash()); !ok {
		t.Error("b4 (above head's view, on the kept chain) was deleted by Prune")
	}
}

func TestPruneTieBreakIsAscendingHash(t *testing.T) {
	s := New()
	main := chain(3, "main")
	for _, b := range main {
		s.Put(b)
	}
	b1, head := main[0], main[2]

	forkA := extend(b1, 1, "a")[0]
	forkB := extend(b1, 1, "b")[0]
	s.Put(forkA)
	s.Put(forkB)

	dropped := s.Prune(head.Hash())

	ha, hb := forkA.Hash(), forkB.Hash()
	first, second := forkA, forkB
	if bytes.Compare(ha[:], hb[:]) > 0 {
		first, second = forkB, forkA
	}

	if len(dropped) != 2 || dropped[0] != first || dropped[1] != second {
		t.Fatalf("Prune returned %v, want [%p, %p] in ascending hash order", dropped, first, second)
	}
}

func TestPruneUnknownHeadIsNoop(t *testing.T) {
	s := New()
	main := chain(2, "main")
	for _, b := range main {
		s.Put(b)
	}
	before := s.Len()

	unknown := hotstuff.NewBlock(hotstuff.GenesisHash(), 1, 1, hotstuff.QuorumCert{}, [][]byte{[]byte("unstored")})

	dropped := s.Prune(unknown.Hash())

	if dropped != nil {
		t.Errorf("Prune on unknown head returned %v, want nil", dropped)
	}
	if s.Len() != before {
		t.Errorf("Len() after Prune on unknown head = %d, want %d", s.Len(), before)
	}
}

func TestPruneToleratesAncestorGap(t *testing.T) {
	s := New()
	unknownParent := hotstuff.Hash{0xAA}
	gapped := hotstuff.NewBlock(unknownParent, 5, 1, hotstuff.QuorumCert{}, nil)
	s.Put(gapped)
	unrelated := hotstuff.NewBlock(hotstuff.GenesisHash(), 3, 1, hotstuff.QuorumCert{}, [][]byte{[]byte("unrelated")})
	s.Put(unrelated)

	s.Prune(gapped.Hash()) // must not panic

	if _, ok := s.Get(gapped.Hash()); !ok {
		t.Error("gapped block missing after Prune")
	}
	if _, ok := s.Get(unrelated.Hash()); ok {
		t.Error("unrelated block still present after Prune")
	}
	if _, ok := s.Get(hotstuff.GenesisHash()); !ok {
		t.Error("genesis dropped by Prune despite the gap in the ancestor walk")
	}
}

func TestConcurrentGetPut(t *testing.T) {
	s := New()
	seed := chain(10, "seed")
	for _, b := range seed {
		s.Put(b)
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for j := range 50 {
				s.Get(seed[j%len(seed)].Hash())
			}
		})
	}

	fresh := extend(seed[len(seed)-1], 20, "fresh")
	wg.Go(func() {
		for _, b := range fresh {
			s.Put(b)
		}
	})

	wg.Wait()

	for _, b := range fresh {
		if _, ok := s.Get(b.Hash()); !ok {
			t.Errorf("block %x lost under concurrent access", b.Hash())
		}
	}
}

// TestPruneCostIsFlatInChainDepth pins the complexity rather than a number:
// one Prune must cost what arrived since the last one, not what the chain has
// accumulated. Walking head to genesis every commit made this ratio scale
// with depth — roughly 14x across these two — so a generous bound still
// catches a regression without being flaky.
func TestPruneCostIsFlatInChainDepth(t *testing.T) {
	perPrune := func(depth int) time.Duration {
		s := New()
		blocks := chain(depth, "main")
		for _, b := range blocks {
			s.Put(b)
		}
		start := time.Now()
		for _, b := range blocks { // one Prune per commit, as Core.execute does
			s.Prune(b.Hash())
		}
		return time.Since(start) / time.Duration(depth)
	}

	perPrune(1000) // warm up, so first-run costs stay out of the ratio
	shallow, deep := perPrune(1000), perPrune(8000)
	if deep > 4*shallow {
		t.Errorf("Prune costs %v per commit at depth 8000 against %v at depth 1000, want no scaling with depth", deep, shallow)
	}
	t.Logf("per Prune: depth 1000 %v, depth 8000 %v", shallow, deep)
}

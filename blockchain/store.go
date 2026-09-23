// Package blockchain holds the shared, content-addressed block store.
package blockchain

import (
	"bytes"
	"cmp"
	"slices"
	"sync"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Store is an in-memory, content-addressed block store. It is the only shared
// mutable protocol state, so it is guarded by an RWMutex: consensus runs on one
// goroutine but the Fetch responder answers on a Gorums handler goroutine.
type Store struct {
	mu     sync.RWMutex
	blocks map[hotstuff.Hash]*hotstuff.Block

	// prunedView is the view of the head the last Prune ran for. Every stored
	// block at or below it is an ancestor of that head, and heads only ever
	// advance along one chain, so it is an ancestor of every later head too.
	// That is what lets the ancestor walk and the candidate scan both stop
	// there instead of running back to genesis on every commit.
	prunedView hotstuff.View
	// byView indexes the blocks stored above prunedView — the only ones a
	// Prune can still drop — so a Prune reads exactly the views its commit
	// closed and leaves the pipeline above the head untouched.
	byView map[hotstuff.View][]*hotstuff.Block
}

// New returns a store already holding the genesis block, so that a chain walk
// always terminates.
func New() *Store {
	s := &Store{
		blocks: make(map[hotstuff.Hash]*hotstuff.Block),
		byView: make(map[hotstuff.View][]*hotstuff.Block),
	}
	s.blocks[hotstuff.GenesisHash()] = hotstuff.Genesis()
	return s
}

// Get returns the block for h, if stored.
func (s *Store) Get(h hotstuff.Hash) (*hotstuff.Block, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.blocks[h]
	return b, ok
}

// Put stores b. Storing an already-present hash is a no-op.
func (s *Store) Put(b *hotstuff.Block) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := b.Hash()
	if _, ok := s.blocks[h]; ok {
		return
	}
	s.blocks[h] = b
	// A block at or below the last pruned head's view reaches the store only
	// as a backfilled ancestor of the committed chain, so it is kept rather
	// than judged: the truncated walk could not tell it from an old fork.
	if v := b.View(); v > s.prunedView {
		s.byView[v] = append(s.byView[v], b)
	}
}

// Prune drops every block that can no longer be committed — one whose view is at
// or below head's and that is neither genesis nor an ancestor of head — and
// returns them in descending view order, ties broken by ascending hash, so the
// newest abandoned fork comes first — a client layer may want to abort them.
// If head is not stored, it is a no-op.
//
// Heads only advance along one chain, so blocks already settled below an
// earlier head are kept without being looked at again: one call costs what
// arrived since the last one, not what the chain has accumulated. Committed
// blocks are never dropped, which is what keeps a lagging peer's backfill
// answerable — and what makes the store grow for the life of the process.
func (s *Store) Prune(head hotstuff.Hash) []*hotstuff.Block {
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.blocks[head]
	if !ok {
		return nil
	}
	hv := h.View()
	if hv <= s.prunedView {
		return nil // everything that far back is already settled as an ancestor
	}

	ancestors := map[hotstuff.Hash]bool{}
	for cur, ok := h, true; ok && cur.View() > s.prunedView; {
		ancestors[cur.Hash()] = true
		cur, ok = s.blocks[cur.Parent()]
	}

	var dropped []*hotstuff.Block
	sweep := func(v hotstuff.View) {
		for _, b := range s.byView[v] {
			if ancestors[b.Hash()] {
				continue // settled below the head, and never prunable again
			}
			dropped = append(dropped, b)
			delete(s.blocks, b.Hash())
		}
		delete(s.byView, v)
	}
	// Whichever sweep is shorter: the views this commit closed, or the views
	// still open. A commit that jumps a long run of empty views must not cost
	// a step for each of them.
	if int(hv-s.prunedView) <= len(s.byView) {
		for v := s.prunedView + 1; v <= hv; v++ {
			sweep(v)
		}
	} else {
		for v := range s.byView {
			if v <= hv {
				sweep(v)
			}
		}
	}
	s.prunedView = hv

	slices.SortFunc(dropped, func(a, b *hotstuff.Block) int {
		ah, bh := a.Hash(), b.Hash()
		return cmp.Or(cmp.Compare(b.View(), a.View()), bytes.Compare(ah[:], bh[:]))
	})
	return dropped
}

// Len is the number of stored blocks.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blocks)
}

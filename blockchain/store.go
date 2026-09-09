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
}

var _ hotstuff.BlockStore = (*Store)(nil)

// New returns a store already holding the genesis block, so that a chain walk
// always terminates.
func New() *Store {
	s := &Store{blocks: make(map[hotstuff.Hash]*hotstuff.Block)}
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
}

// Prune drops every block that can no longer be committed — one whose view is at
// or below head's and that is neither genesis nor an ancestor of head — and
// returns them in descending view order, ties broken by ascending hash, so the
// newest abandoned fork comes first. If head is not stored, it is a no-op.
func (s *Store) Prune(head hotstuff.Hash) []*hotstuff.Block {
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.blocks[head]
	if !ok {
		return nil
	}
	hv := h.View()

	ancestors := map[hotstuff.Hash]bool{}
	for cur, ok := h, true; ok; {
		ancestors[cur.Hash()] = true
		cur, ok = s.blocks[cur.Parent()]
	}

	var dropped []*hotstuff.Block
	for hash, b := range s.blocks {
		// Genesis is the store's root and is never prunable: a chain walk has
		// to terminate even when head's ancestors are not all stored.
		if b.View() == 0 || b.View() > hv || ancestors[hash] {
			continue
		}
		dropped = append(dropped, b)
	}
	for _, b := range dropped {
		delete(s.blocks, b.Hash())
	}

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

package diem

// MemLedger is the in-memory ledger (paper 3.2): a branching tree of
// speculative states extending the last committed one, plus the committed
// blocks LeaderElection walks back over.
//
// The speculation tree is what lets a vote certify an execution result and not
// just an ordering. A replica whose VM diverges speculates a different state
// id, so its vote aggregates under a different key and never joins the quorum —
// the divergence shows up as a stalled round rather than as silent corruption.
type MemLedger struct {
	// Execute is the VM. It must be deterministic across replicas; that is the
	// whole assumption DiemBFT's execution certification rests on.
	Execute func(prev Hash, payload [][]byte) Hash

	// OnCommit, if set, runs once per block in commit order. It is where a
	// replicated application consumes the chain; the paper leaves it to the
	// "higher level logic" the Ledger module is the gateway for.
	OnCommit func(*Block)

	// History bounds the committed blocks kept for LeaderElection, which walks
	// back window_size blocks and far enough to collect exclude_size authors.
	// A persistent ledger store would keep them all; this one is a prototype
	// and must not grow without bound during a long run.
	History int

	pending   map[Hash]speculated
	committed map[Hash]*Block
	order     []Hash // committed ids, oldest first

	commitID    Hash
	commitState Hash
}

type speculated struct {
	block *Block
	state Hash
}

const defaultHistory = 512

// NewMemLedger returns a ledger with genesis committed. Genesis gets a
// non-zero state id on purpose: a zero CommitStateID is the paper's bottom,
// so a genesis state of zero would make the first commit indistinguishable
// from no commit at all.
func NewMemLedger() *MemLedger {
	l := &MemLedger{
		Execute:   ExecuteHash,
		History:   defaultHistory,
		pending:   map[Hash]speculated{},
		committed: map[Hash]*Block{},
	}
	l.commitID = genesisBlock.ID()
	l.commitState = ExecuteHash(Hash{}, nil)
	l.committed[l.commitID] = genesisBlock
	l.order = append(l.order, l.commitID)
	return l
}

// Speculate executes b over its parent's state. A parent this replica never
// speculated leaves nothing stored and returns the zero state, and this is
// where the paper's missing block-sync lands.
//
// Section 3 defines no way to fetch a block, so a replica that loses one
// proposal cannot speculate it, cannot vote on it, and cannot speculate its
// children either. Commit cannot walk back across the gap to move the frontier,
// so it does not recover: the replica is out of the quorum for good. The
// protocol is shipped as written rather than extended with a sync path, and
// PendingState reporting false is how Safety learns to decline —
// Safety.DeclinedMissingAncestor counts what that costs.
//
// The paper's signature is speculate(prev_block_id, block_id, txns). All
// three are fields of b, and committed_block must hand a whole block back,
// so the ledger has to hold the block in any case.
func (l *MemLedger) Speculate(b *Block) Hash {
	prev, ok := l.PendingState(b.ParentID())
	if !ok {
		return Hash{}
	}
	state := l.Execute(prev, b.Payload)
	l.pending[b.ID()] = speculated{block: b, state: state}
	return state
}

// PendingState is the speculated state for a block. The last committed block
// answers too: its children extend it, and it is no longer pending.
func (l *MemLedger) PendingState(blockID Hash) (Hash, bool) {
	if blockID == l.commitID {
		return l.commitState, true
	}
	s, ok := l.pending[blockID]
	return s.state, ok
}

// Commit exports the pending prefix ending at blockID and discards the
// branches forking below it.
func (l *MemLedger) Commit(blockID Hash) {
	if blockID == l.commitID {
		return // already committed; the common case, since every QC re-commits
	}
	// Walk back to the commit frontier, then apply forward so the ledger sees
	// commit order.
	var chain []speculated
	for id := blockID; id != l.commitID; {
		s, ok := l.pending[id]
		if !ok {
			return // blockID is not a descendant of the frontier: nothing to do
		}
		chain = append(chain, s)
		id = s.block.ParentID()
	}
	for i := len(chain) - 1; i >= 0; i-- {
		s := chain[i]
		id := s.block.ID()
		delete(l.pending, id)
		l.committed[id] = s.block
		l.order = append(l.order, id)
		l.commitID, l.commitState = id, s.state
		if l.OnCommit != nil {
			l.OnCommit(s.block)
		}
	}
	l.prune()
	l.forget()
}

// CommittedBlock returns a committed block by id.
func (l *MemLedger) CommittedBlock(blockID Hash) (*Block, bool) {
	b, ok := l.committed[blockID]
	return b, ok
}

// prune drops speculated states that can no longer be reached from the commit
// frontier. A block survives only while its parent does, so deleting the
// orphans repeatedly until nothing changes removes whole abandoned branches.
func (l *MemLedger) prune() {
	for changed := true; changed; {
		changed = false
		for id, s := range l.pending {
			parent := s.block.ParentID()
			if parent == l.commitID {
				continue
			}
			if _, ok := l.pending[parent]; !ok {
				delete(l.pending, id)
				changed = true
			}
		}
	}
}

// forget drops the oldest committed blocks past the retention bound.
func (l *MemLedger) forget() {
	for len(l.order) > l.History {
		id := l.order[0]
		l.order = l.order[1:]
		if id != l.commitID {
			delete(l.committed, id)
		}
	}
}

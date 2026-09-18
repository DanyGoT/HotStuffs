package diem

import "github.com/DanyGoT/HotStuffs/hotstuff"

// This file holds every seam the protocol plugs into. The modules in the paper
// that are left abstract — Ledger (3.2) and MemPool (3.6) — are interfaces
// here, as is the network, so the whole protocol runs in a deterministic
// in-memory harness.

// Ledger is the gateway to the ledger store (paper 3.2). It maintains a local,
// branching tree of speculative states extending the last committed state, and
// keeps the committed blocks that LeaderElection walks back over.
type Ledger interface {
	// Speculate executes b's payload over the state speculated for b's parent
	// and returns the resulting state id.
	//
	// The paper's signature is speculate(prev_block_id, block_id, txns). All
	// three are fields of b, and committed_block must hand a whole block back,
	// so the ledger has to hold the block in any case.
	Speculate(b *Block) Hash
	// PendingState is the speculated state for a block, or false if that block
	// was never speculated.
	PendingState(blockID Hash) (Hash, bool)
	// Commit exports the pending prefix ending at blockID and discards the
	// branches that fork below it. Committing a block already committed, or
	// one never speculated, does nothing.
	Commit(blockID Hash)
	// CommittedBlock returns a committed block by id.
	CommittedBlock(blockID Hash) (*Block, bool)
}

// MemPool supplies the payload for a leader's proposal (paper 3.6).
type MemPool interface{ GetTransactions() [][]byte }

// Transport is the outbound half of the network. Every method is safe to call
// from the consensus goroutine, never blocks, and returns no error: a BFT
// replica cannot act on a send failure, and the round timer is the recovery
// mechanism.
type Transport interface {
	// Proposal sends to all replicas, this one included.
	Proposal(*ProposalMsg)
	// Vote sends to one replica: the leader of the next round. This is the
	// paper's unicast, and it is why only that leader accumulates a QC.
	Vote(*VoteMsg, ID)
	// Timeout sends to all replicas, this one included.
	Timeout(*TimeoutMsg)
}

// EventSink accepts events from any goroutine. Only the round timer uses it:
// its callback runs off the consensus goroutine, so it may enqueue and nothing
// else.
type EventSink interface{ Push(Event) }

// Clock, Timer and ViewDuration are package hotstuff's, unchanged: the round
// timer has the same shape in both protocols, and sharing them means one fake
// clock serves both harnesses.
type (
	Clock         = hotstuff.Clock
	Timer         = hotstuff.Timer
	RoundDuration = hotstuff.ViewDuration
)

// Crypto signs and verifies digests. DiemBFT aggregates nothing, so a
// certificate is a slice of signatures and there is no combine step.
type Crypto = hotstuff.Crypto

package hotstuff

import "time"

// This file holds every seam the implementation plugs into. Read it first: the
// protocol core talks to the outside world only through the interfaces below,
// which is what keeps protobuf and Gorums out of the core and lets the whole
// protocol run in a deterministic in-memory harness.

// EventSink accepts authenticated events from any goroutine.
type EventSink interface{ Push(Event) }

// Transport is the outbound half of the network. Every method is safe to call
// from the consensus goroutine, never blocks, and never returns an error: a BFT
// replica cannot act on a send error, and the view timer is the recovery
// mechanism. Failures are counted instead.
type Transport interface {
	// Propose sends to all replicas, this one included.
	Propose(Proposal)
	// Vote sends to all replicas, this one included. The paper unicasts a vote
	// to the leader of the next view; that mapping stalls commits whenever a
	// crashed replica is both a leader and the preceding view's collector, so
	// every replica collects instead. See .claude/logs for the measurement.
	Vote(PartialCert)
	// Timeout sends to all replicas, this one included.
	Timeout(TimeoutMsg)
	// Fetch asks the configuration for a block by hash. The answer arrives as
	// a FetchedEvent, or never.
	Fetch(Hash)
}

// Crypto signs and verifies message digests. A QuorumCert is just a slice of
// signatures, so there is no separate combine step.
type Crypto interface {
	Sign(msg Hash) (Signature, error)
	Verify(msg Hash, sig Signature) bool
	// VerifyQuorum reports whether sigs holds at least quorum distinct valid
	// signatures over msg. Implementations may batch-verify.
	VerifyQuorum(msg Hash, sigs []Signature) bool
}

// LeaderRotation names the leader of a view. A func, not an interface: the
// strategy is stateless.
type LeaderRotation func(View) ID

// RoundRobin rotates the leadership over replica IDs 1..n.
func RoundRobin(n int) LeaderRotation {
	return func(v View) ID { return ID(uint64(v)%uint64(n)) + 1 }
}

// Clock is the time source. The deterministic harness supplies a fake one.
type Clock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) Timer
}

// Timer is a pending Clock.AfterFunc callback.
type Timer interface{ Stop() bool }

// CommandQueue is the source of commands to propose. Poll must not block; it
// reports false when there is nothing to propose.
type CommandQueue interface{ Poll() ([][]byte, bool) }

// Executor consumes committed blocks in commit order. Exec must not block.
type Executor interface{ Exec(*Block) }

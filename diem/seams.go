package diem

import (
	"time"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// Transport is the outbound half of the network. Every method is safe to call
// from the consensus goroutine, never blocks, and returns no error: a BFT
// replica cannot act on a send failure, and the round timer is the recovery
// mechanism.
type Transport interface {
	// Proposal sends to all replicas, this one included.
	Proposal(*diempb.ProposalMsg)
	// Vote sends to one replica: the leader of the next round. This is the
	// paper's unicast, and it is why only that leader accumulates a QC.
	Vote(*diempb.VoteMsg, uint32)
	// Timeout sends to all replicas, this one included.
	Timeout(*diempb.TimeoutMsg)
}

// Crypto signs and verifies digests. DiemBFT aggregates nothing, so a
// certificate is a slice of signatures and there is no combine step.
type Crypto interface {
	Sign(digest []byte) ([]byte, error)
	// Verify checks sig against the public key registered for signer.
	Verify(signer uint32, digest, sig []byte) bool
}

// Clock is the time source. The deterministic harness supplies a fake one.
type Clock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) Timer
}

// Timer is a pending Clock.AfterFunc callback.
type Timer interface{ Stop() bool }

// SystemClock is the wall-clock Clock. time.AfterFunc runs its callback on its
// own goroutine, which is why a timer callback may only enqueue an event.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

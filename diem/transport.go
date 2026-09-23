package diem

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

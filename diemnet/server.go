package diemnet

import (
	"sync/atomic"

	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
)

// handler is the inbound half of the transport. Every message is verified
// here, on the Gorums handler goroutine that already runs in parallel across
// senders, so no signature check ever reaches the consensus goroutine.
//
// GORUMS: ServerContext exposes no authenticated sender identity — the
// gorums-node-id metadata key is internal, and peer.FromContext gives an
// address, not an identity. Every message therefore carries its sender
// explicitly and is authenticated by signature, never by connection. That costs
// little, since BFT requires content authentication regardless, but it is why
// the ServerContext is unused in all three handlers.
//
// The handlers deliberately do not call ctx.Release(). Gorums processes one
// sender's requests in receipt order while the handler holds the lock, and that
// per-sender FIFO is wanted: a leader's proposals must be seen in round order,
// or a proposal arrives before its parent and, with no block-sync in DiemBFT
// §3, this replica declines to vote on it for good.
type handler struct {
	ver  *diem.Verifier
	sink func(diem.Event)

	rejected atomic.Uint64
}

var _ diempb.DiemServer = (*handler)(nil)

func (h *handler) Proposal(_ gorums.ServerContext, in *diempb.ProposalMsg) {
	if !h.ver.VerifyProposal(in) {
		h.rejected.Add(1)
		return
	}
	h.sink(diem.ProposalEvent{Msg: in})
}

func (h *handler) Vote(_ gorums.ServerContext, in *diempb.VoteMsg) {
	if !h.ver.VerifyVote(in) {
		h.rejected.Add(1)
		return
	}
	h.sink(diem.VoteEvent{Msg: in})
}

func (h *handler) Timeout(_ gorums.ServerContext, in *diempb.TimeoutMsg) {
	if !h.ver.VerifyTimeout(in) {
		h.rejected.Add(1)
		return
	}
	h.sink(diem.TimeoutEvent{Msg: in})
}

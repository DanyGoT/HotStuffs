package network

import (
	"fmt"
	"sync/atomic"

	"github.com/DanyGoT/HotStuffs/blockchain"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/hotstuffpb"
	"github.com/relab/gorums"
)

// handler is the inbound half of the transport. Every message is converted and
// verified here, on the Gorums handler goroutine that already runs in parallel
// across senders, so no signature check ever reaches the consensus goroutine.
//
// GORUMS: ServerContext exposes no authenticated sender identity — the
// gorums-node-id metadata key is internal, and peer.FromContext gives an
// address, not an identity. Every message therefore carries its sender
// explicitly and is authenticated by signature, never by connection. That costs
// little, since BFT requires content authentication regardless, but it is why
// the ServerContext is unused in all three one-way handlers.
//
// The one-way handlers deliberately do not call ctx.Release(). Gorums processes
// one sender's requests in receipt order while the handler holds the lock, and
// that per-sender FIFO is wanted: proposals from one leader must be seen in
// view order, or a proposal arrives before its parent and costs an avoidable
// backfill.
type handler struct {
	ver   *hotstuff.Verifier
	sink  hotstuff.EventSink
	store *blockchain.Store

	rejected atomic.Uint64
}

var _ hotstuffpb.HotStuffServer = (*handler)(nil)

func (h *handler) Propose(_ gorums.ServerContext, in *hotstuffpb.Proposal) {
	p, err := fromProposal(in)
	if err != nil || !h.ver.VerifyProposal(p) {
		h.rejected.Add(1)
		return
	}
	h.sink.Push(hotstuff.ProposeEvent{Proposal: p})
}

func (h *handler) Vote(_ gorums.ServerContext, in *hotstuffpb.VoteMsg) {
	cert, err := fromVote(in)
	if err != nil || !h.ver.VerifyVote(cert) {
		h.rejected.Add(1)
		return
	}
	h.sink.Push(hotstuff.VoteEvent{PartialCert: cert})
}

func (h *handler) Timeout(_ gorums.ServerContext, in *hotstuffpb.TimeoutMsg) {
	m, err := fromTimeout(in)
	if err != nil || !h.ver.VerifyTimeout(m) {
		h.rejected.Add(1)
		return
	}
	h.sink.Push(hotstuff.TimeoutEvent{TimeoutMsg: m})
}

// Fetch answers a backfill request straight from the store. It is not an event:
// it touches no protocol state, which is why the store carries an RWMutex.
func (h *handler) Fetch(ctx gorums.ServerContext, in *hotstuffpb.BlockHash) (*hotstuffpb.Block, error) {
	// The only handler that releases. Serving a block needs no exclusive
	// access, and a backfill must not hold up the requester's other messages.
	ctx.Release()
	hash, err := fromHash(in.GetHash())
	if err != nil {
		return nil, err
	}
	b, ok := h.store.Get(hash)
	if !ok {
		return nil, fmt.Errorf("block %x not stored", hash[:8])
	}
	return toBlock(b), nil
}

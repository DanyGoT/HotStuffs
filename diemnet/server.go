package diemnet

import (
	"errors"
	"sync/atomic"

	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
)

// handler is the inbound half of the transport. Every message is verified
// here, on the Gorums handler goroutine, so messages from different senders are
// authenticated in parallel before they reach the core.
//
// GORUMS: ServerContext exposes no authenticated sender identity — the
// gorums-node-id metadata key is internal, and peer.FromContext gives an
// address, not an identity. Every message therefore carries its sender
// explicitly and is authenticated by signature, never by connection. That costs
// little, since BFT requires content authentication regardless, but it is why
// the ServerContext is unused in the three one-way handlers.
//
// Those handlers deliberately do not call ctx.Release(). Gorums processes one
// sender's requests in receipt order, each after the last handler returns, and
// that per-sender FIFO is wanted: a leader's proposals must be seen in round
// order, or a proposal arrives before its parent and this replica declines to
// vote until it has fetched the parent.
type handler struct {
	ver  *diem.Verifier
	sink func(any)

	rejected atomic.Uint64
}

var _ diempb.DiemServer = (*handler)(nil)

func (h *handler) Proposal(_ gorums.ServerContext, in *diempb.ProposalMsg) {
	if !h.ver.VerifyProposal(in) {
		h.rejected.Add(1)
		return
	}
	h.sink(in)
}

func (h *handler) Vote(_ gorums.ServerContext, in *diempb.VoteMsg) {
	if !h.ver.VerifyVote(in) {
		h.rejected.Add(1)
		return
	}
	h.sink(in)
}

func (h *handler) Timeout(_ gorums.ServerContext, in *diempb.TimeoutMsg) {
	if !h.ver.VerifyTimeout(in) {
		h.rejected.Add(1)
		return
	}
	h.sink(in)
}

var errNoBlock = errors.New("diemnet: block not held")

// RequestBlock is answered by the core, which owns the blocks. A replica that
// has stopped does not answer, and the request ends with its context.
func (h *handler) RequestBlock(ctx gorums.ServerContext, in *diempb.BlockHash) (*diempb.Block, error) {
	reply := make(chan *diempb.Block, 1)
	h.sink(func(c *diem.Core) { reply <- c.Block(in.GetId()) })
	ctx.Release()
	select {
	case b := <-reply:
		if b == nil {
			return nil, errNoBlock
		}
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

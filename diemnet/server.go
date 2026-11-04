package diemnet

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
)

// handler is the inbound half of the transport. Every message is verified
// here, on the Gorums handler goroutine, so messages from different senders are
// authenticated in parallel before the handler calls the core under the
// replica's lock.
//
// GORUMS: ServerContext exposes no authenticated sender identity — the
// gorums-node-id metadata key is internal, and peer.FromContext gives an
// address, not an identity. Every message therefore carries its sender
// explicitly and is authenticated by signature, never by connection. That costs
// little, since BFT requires content authentication regardless, but it is why
// the ServerContext is unused in the three one-way handlers.
//
// Those handlers deliberately do not call ctx.Release(). Gorums holds back a
// sender's next request until the handler returns, and that per-sender FIFO is
// wanted: a leader's proposals must be seen in round order, or a proposal
// arrives before its parent and this replica declines to vote until it has
// fetched the parent.
type handler struct {
	ver  *diem.Verifier
	core *diem.Core
	mu   sync.Locker // the replica's lock, which serializes every core call

	rejected atomic.Uint64
}

var _ diempb.DiemServer = (*handler)(nil)

func (h *handler) Proposal(_ gorums.ServerContext, in *diempb.ProposalMsg) {
	if !h.ver.VerifyProposal(in) {
		h.rejected.Add(1)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnProposal(in)
}

func (h *handler) Vote(_ gorums.ServerContext, in *diempb.VoteMsg) {
	if !h.ver.VerifyVote(in) {
		h.rejected.Add(1)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnVote(in)
}

func (h *handler) Timeout(_ gorums.ServerContext, in *diempb.TimeoutMsg) {
	if !h.ver.VerifyTimeout(in) {
		h.rejected.Add(1)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnTimeout(in)
}

var errNoBlock = errors.New("diemnet: block not held")

// RequestBlock answers from the core, which owns the blocks.
func (h *handler) RequestBlock(_ gorums.ServerContext, in *diempb.BlockHash) (*diempb.Block, error) {
	h.mu.Lock()
	b := h.core.Block(in.GetId())
	h.mu.Unlock()
	if b == nil {
		return nil, errNoBlock
	}
	return b, nil
}

// block hands a fetched block to the core.
func (h *handler) block(b *diempb.Block) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnBlock(b)
}

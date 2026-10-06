// Package diem implements the DiemBFT v4 pseudocode of the paper's Section 3,
// one file per module: Ledger (3.2), Block-tree (3.3), Safety (3.4), Pacemaker
// (3.5), MemPool (3.6), LeaderElection (3.7) and the Main event loop (3.1).
// It commits on a contiguous 2-chain and signs a LedgerCommitInfo.
//
// It works directly on the generated diempb messages, which are read-only once
// built. Rounds are uint64 and replica ids uint32, as on the wire; hashes are
// 32-byte slices, keyed in maps by string(h) and compared with bytes.Equal.
package diem

import (
	"slices"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// zeroHash is the paper's bottom: a LedgerCommitInfo carrying it as its
// CommitStateId commits nothing.
var zeroHash [hashLen]byte

// NewBlock builds a block and fills its id, the digest the core trusts from
// then on.
func NewBlock(author uint32, round uint64, payload [][]byte, qc *diempb.QuorumCert) *diempb.Block {
	return diempb.Block_builder{
		Author:  author,
		Round:   round,
		Payload: payload,
		Qc:      qc,
		Id:      blockID(author, round, payload, qc),
	}.Build()
}

// QCRound is the round of the block qc certifies; an absent qc is round 0.
func QCRound(qc *diempb.QuorumCert) uint64 { return qc.GetVoteInfo().GetRound() }

// higher returns whichever of a and b certifies the later round, preferring b
// on a tie. It is the paper's max_round.
func higher(a, b *diempb.QuorumCert) *diempb.QuorumCert {
	if QCRound(a) > QCRound(b) {
		return a
	}
	return b
}

func parentID(b *diempb.Block) []byte { return b.GetQc().GetVoteInfo().GetId() }

// Commits reports whether a quorum over l commits a block: its CommitStateId is
// not the paper's bottom, the all-zero hash.
func Commits(l *diempb.LedgerCommitInfo) bool {
	return slices.ContainsFunc(l.GetCommitStateId(), func(b byte) bool { return b != 0 })
}

// MaxHighQCRound is the highest certified round any signer of tc reported. A
// block entering tc.Round+1 may not extend a QC below it: that is the round
// below which the quorum has guaranteed nothing was committed.
func MaxHighQCRound(tc *diempb.TimeoutCert) uint64 {
	var highest uint64
	for _, v := range tc.GetVotes() {
		highest = max(highest, v.GetHighQcRound())
	}
	return highest
}

// WellFormedProposal is the paper's well-formedness rule for a round-r
// message: it must carry the TC of round r-1 exactly when its certificate is
// not from r-1. Honest replicas discard everything else, so this is checked
// before a message is allowed to touch any state.
func WellFormedProposal(p *diempb.ProposalMsg) bool {
	b := p.GetBlock()
	return b != nil && b.GetQc() != nil &&
		wellFormed(b.GetRound(), QCRound(b.GetQc()), p.GetLastRoundTc())
}

// WellFormedTimeout is the rule of WellFormedProposal, for a timeout.
func WellFormedTimeout(m *diempb.TimeoutMsg) bool {
	t := m.GetTmoInfo()
	return t.GetHighQc() != nil &&
		wellFormed(t.GetRound(), QCRound(t.GetHighQc()), m.GetLastRoundTc())
}

func wellFormed(round, qcRound uint64, tc *diempb.TimeoutCert) bool {
	if round == 0 {
		return false
	}
	if qcRound+1 == round {
		return tc == nil // the QC alone justifies the round; a TC is irrelevant
	}
	return tc != nil && tc.GetRound()+1 == round
}

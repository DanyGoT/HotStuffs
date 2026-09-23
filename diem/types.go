// Package diem implements the DiemBFT v4 pseudocode of the paper's Section 3,
// one file per module: Ledger (3.2), Block-tree (3.3), Safety (3.4), Pacemaker
// (3.5), MemPool (3.6), LeaderElection (3.7) and the Main event loop (3.1).
// The transcribed pseudocode is in .claude/notes/diembft-pseudocode.md.
//
// It is a sibling of package consensus, not a replacement: that one implements
// Chained HotStuff, which commits on a 3-chain and signs a (view, block) pair,
// where DiemBFT commits on a contiguous 2-chain and signs a LedgerCommitInfo.
// The two protocols share the identity, digest, signature and clock vocabulary
// of package hotstuff, and nothing else.
package diem

import "github.com/DanyGoT/HotStuffs/hotstuff"

// Borrowed from package hotstuff so one Crypto implementation serves both
// protocols. Everything below this line is DiemBFT's own.
type (
	ID        = hotstuff.ID
	Hash      = hotstuff.Hash
	Signature = hotstuff.Signature

	// The round timer has the same shape in both protocols, so one fake clock
	// serves both harnesses.
	Clock = hotstuff.Clock
	Timer = hotstuff.Timer

	// Crypto signs and verifies digests. DiemBFT aggregates nothing, so a
	// certificate is a slice of signatures and there is no combine step.
	Crypto = hotstuff.Crypto
)

// Round is a DiemBFT round. The paper's rounds are HotStuff's views under
// another name, but the two protocols advance them differently, so the type
// stays separate.
type Round uint64

// VoteInfo is what a vote says about the block it is cast for. The parent's id
// and round are carried for convenience: they let a receiver decide commitment
// from a single block, without fetching its ancestors. ExecStateID is the
// speculated execution result, which is what makes a quorum certify the
// outcome of the transactions and not merely their order.
type VoteInfo struct {
	ID          Hash
	Round       Round
	ParentID    Hash
	ParentRound Round
	ExecStateID Hash
}

// LedgerCommitInfo is the half of a vote a client can check without knowing
// anything about consensus. CommitStateID is a proof of history; VoteInfoHash
// is opaque to clients and binds the same signature to the consensus payload,
// so one signature authenticates both.
//
// A zero CommitStateID is the paper's bottom: this vote's quorum commits
// nothing. Nothing else hashes to zero, so the zero value is unambiguous.
type LedgerCommitInfo struct {
	CommitStateID Hash
	VoteInfoHash  Hash
}

// Commits reports whether a quorum over this LedgerCommitInfo commits a block.
func (l LedgerCommitInfo) Commits() bool { return l.CommitStateID != (Hash{}) }

// VoteMsg is one replica's vote. The signature covers LedgerCommitInfo alone —
// VoteInfo is covered through its hash — which is what lets the same signature
// serve consensus and a light client.
type VoteMsg struct {
	VoteInfo         VoteInfo
	LedgerCommitInfo LedgerCommitInfo
	HighCommitQC     *QC // lets a lagging receiver catch up on commits
	Sender           ID
	Sig              Signature
}

// QC is a VoteMsg with a quorum of signatures behind it.
type QC struct {
	VoteInfo         VoteInfo
	LedgerCommitInfo LedgerCommitInfo
	Signatures       []Signature
	Author           ID
	// AuthorSig covers the digest of Signatures. It certifies nothing the
	// quorum does not already certify; it names the replica that assembled
	// this particular set, which is what makes an equivocating aggregator
	// attributable.
	AuthorSig Signature
}

// Round is the round of the block this certificate certifies.
func (q *QC) Round() Round {
	if q == nil {
		return 0
	}
	return q.VoteInfo.Round
}

// higher returns whichever of a and b certifies the later round, preferring a
// on a tie. It is the paper's max_round.
func higher(a, b *QC) *QC {
	if a.Round() > b.Round() {
		return a
	}
	return b
}

// Block is a proposal. Author may differ from QC.Author: after a view change
// the new leader proposes over a certificate somebody else assembled.
type Block struct {
	Author  ID
	Round   Round
	Payload [][]byte
	QC      *QC

	id Hash
}

// NewBlock builds a block and caches its id.
func NewBlock(author ID, round Round, payload [][]byte, qc *QC) *Block {
	b := &Block{Author: author, Round: round, Payload: payload, QC: qc}
	b.id = blockID(author, round, payload, qc)
	return b
}

// ID is the cached block digest.
func (b *Block) ID() Hash { return b.id }

// ParentID is the id of the block this one extends.
func (b *Block) ParentID() Hash { return b.QC.VoteInfo.ID }

// TimeoutInfo reports that its sender gave up on Round. The signature covers
// (Round, HighQC.Round), so timeouts for one round aggregate into a TC even
// though their senders hold different highest certificates.
type TimeoutInfo struct {
	Round  Round
	HighQC *QC
	Sender ID
	Sig    Signature
}

// TimeoutVote is one signer's contribution to a TC.
//
// The paper keeps a TC's high_qc rounds and signatures in two parallel vectors.
// One slice of pairs holds the same information and cannot be misaligned,
// which matters because each signature covers (tc.Round, its own HighQCRound)
// and verifying against the wrong partner would silently succeed for a
// different sender.
type TimeoutVote struct {
	HighQCRound Round
	Sig         Signature
}

// TC certifies that a quorum abandoned Round. It is the evidence that entitles
// the next round's leader to propose without a QC from Round.
type TC struct {
	Round Round
	Votes []TimeoutVote
}

// MaxHighQCRound is the highest certified round any signer reported. A block
// entering Round+1 on this TC may not extend a QC below it: that is the round
// below which the quorum has guaranteed nothing was committed.
func (t *TC) MaxHighQCRound() Round {
	if t == nil {
		return 0
	}
	var max Round
	for _, v := range t.Votes {
		if v.HighQCRound > max {
			max = v.HighQCRound
		}
	}
	return max
}

// TimeoutMsg is a broadcast TimeoutInfo. LastRoundTC is the TC for
// TmoInfo.Round-1, required exactly when TmoInfo.HighQC is not from that round.
type TimeoutMsg struct {
	TmoInfo      TimeoutInfo
	LastRoundTC  *TC
	HighCommitQC *QC
}

// ProposalMsg carries a leader's block. LastRoundTC is the TC for
// Block.Round-1, required exactly when Block.QC is not from that round.
type ProposalMsg struct {
	Block        *Block
	LastRoundTC  *TC
	HighCommitQC *QC
	Sender       ID
	Sig          Signature // over Block.ID()
}

// WellFormed is the paper's well-formedness rule for a round-r message: it must
// carry the TC of round r-1 exactly when its certificate is not from r-1.
// Honest replicas discard everything else, so this is checked before a message
// is allowed to touch any state.
func (p *ProposalMsg) WellFormed() bool {
	return p.Block != nil && p.Block.QC != nil &&
		wellFormed(p.Block.Round, p.Block.QC.Round(), p.LastRoundTC)
}

// WellFormed is the rule of ProposalMsg.WellFormed, for a timeout.
func (m *TimeoutMsg) WellFormed() bool {
	return m.TmoInfo.HighQC != nil &&
		wellFormed(m.TmoInfo.Round, m.TmoInfo.HighQC.Round(), m.LastRoundTC)
}

func wellFormed(round, qcRound Round, tc *TC) bool {
	if round == 0 {
		return false
	}
	if qcRound+1 == round {
		return tc == nil // the QC alone justifies the round; a TC is irrelevant
	}
	return tc != nil && tc.Round+1 == round
}

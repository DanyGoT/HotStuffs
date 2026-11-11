package diempb

import "slices"

// Round is the round of the block qc certifies; an absent qc is round 0.
func (qc *QuorumCert) Round() uint64 { return qc.GetVoteInfo().GetRound() }

// Higher returns whichever of qc and other certifies the later round,
// preferring other on a tie. It is the paper's max_round.
func (qc *QuorumCert) Higher(other *QuorumCert) *QuorumCert {
	if qc.Round() > other.Round() {
		return qc
	}
	return other
}

// BlockID is the id of the block qc certifies.
func (qc *QuorumCert) BlockID() []byte { return qc.GetVoteInfo().GetId() }

// ParentID is the id of the block b's certificate certifies.
func (b *Block) ParentID() []byte { return b.GetQc().BlockID() }

// Commits reports whether a quorum over l commits a block: its CommitStateId is
// not the paper's bottom, the all-zero hash.
func (l *LedgerCommitInfo) Commits() bool {
	return slices.ContainsFunc(l.GetCommitStateId(), func(b byte) bool { return b != 0 })
}

// MaxHighQCRound is the highest certified round any signer of tc reported. A
// block entering tc.Round+1 may not extend a QC below it: that is the round
// below which the quorum has guaranteed nothing was committed.
func (tc *TimeoutCert) MaxHighQCRound() uint64 {
	var highest uint64
	for _, v := range tc.GetVotes() {
		highest = max(highest, v.GetHighQcRound())
	}
	return highest
}

// WellFormed is the paper's well-formedness rule for a round-r message: it
// must carry the TC of round r-1 exactly when its certificate is not from r-1.
// Honest replicas discard everything else, so this is checked before a message
// is allowed to touch any state.
func (p *ProposalMsg) WellFormed() bool {
	b := p.GetBlock()
	return b != nil && b.GetQc() != nil &&
		wellFormed(b.GetRound(), b.GetQc().Round(), p.GetLastRoundTc())
}

// WellFormed is the rule of ProposalMsg.WellFormed, for a timeout.
func (m *TimeoutMsg) WellFormed() bool {
	t := m.GetTmoInfo()
	return t.GetHighQc() != nil &&
		wellFormed(t.GetRound(), t.GetHighQc().Round(), m.GetLastRoundTc())
}

func wellFormed(round, qcRound uint64, tc *TimeoutCert) bool {
	if round == 0 {
		return false
	}
	if qcRound+1 == round {
		return tc == nil // the QC alone justifies the round; a TC is irrelevant
	}
	return tc != nil && tc.GetRound()+1 == round
}

package diem

// Safety is the paper's Safety module (3.4): the core consensus safety rules
// and the only holder of the private key.
//
// It keeps exactly two counters — the last round voted in and the highest
// certified round it has endorsed — which is what allows the whole module to
// be deployed inside a trusted hardware component. Everything else it needs
// arrives as an argument or comes from the ledger.
type Safety struct {
	id     ID
	verify *Verifier
	crypto Crypto
	ledger *MemLedger
	tree   *BlockTree

	highestVoteRound Round
	highestQCRound   Round

	declinedMissingAncestor uint64
}

// NewSafety returns the safety module for replica id. It re-verifies through
// verify rather than trusting what the edge already checked.
func NewSafety(id ID, verify *Verifier, crypto Crypto, ledger *MemLedger, tree *BlockTree) *Safety {
	return &Safety{id: id, verify: verify, crypto: crypto, ledger: ledger, tree: tree}
}

// HighestVoteRound is the last round this replica voted or timed out in.
func (s *Safety) HighestVoteRound() Round { return s.highestVoteRound }

// HighestQCRound is the highest certified round this replica has endorsed by
// voting over it.
func (s *Safety) HighestQCRound() Round { return s.highestQCRound }

// DeclinedMissingAncestor counts the votes withheld because the block's
// ancestry was never speculated. It is monotonic, and it is the only measure of
// what having no block-sync costs: see MemLedger.Speculate.
func (s *Safety) DeclinedMissingAncestor() uint64 { return s.declinedMissingAncestor }

func (s *Safety) increaseHighestVoteRound(round Round) {
	s.highestVoteRound = max(round, s.highestVoteRound)
}

func (s *Safety) updateHighestQCRound(qcRound Round) {
	s.highestQCRound = max(qcRound, s.highestQCRound)
}

func consecutive(blockRound, round Round) bool { return round+1 == blockRound }

// safeToExtend allows a block that skips rounds, but only behind a TC for the
// round directly below it, and only when its certificate is at least as high
// as every certificate that TC's quorum reported. That second half is what
// stops a new leader from forking below something already committed: the
// quorum has vouched that nothing above MaxHighQCRound was certified by them.
func (s *Safety) safeToExtend(blockRound, qcRound Round, tc *TC) bool {
	if tc == nil {
		return false
	}
	return consecutive(blockRound, tc.Round) && qcRound >= tc.MaxHighQCRound()
}

func (s *Safety) safeToVote(blockRound, qcRound Round, tc *TC) bool {
	// 1. vote in monotonically increasing rounds
	// 2. a block must extend a round below its own
	if blockRound <= max(s.highestVoteRound, qcRound) {
		return false
	}
	// Either the block extends the QC of the round directly below it, or a TC
	// for that round justifies the gap.
	return consecutive(blockRound, qcRound) || s.safeToExtend(blockRound, qcRound, tc)
}

// safeToTimeout refuses to abandon a round whose entry was never justified,
// and refuses to report a high_qc below one already endorsed — that report is
// what a later leader's safeToExtend check trusts.
func (s *Safety) safeToTimeout(round, qcRound Round, tc *TC) bool {
	if qcRound < s.highestQCRound {
		return false
	}
	// The paper writes max(highest_vote_round - 1, qc_round); rounds are
	// unsigned, so round 0 is subtracted explicitly rather than wrapping.
	var voted Round
	if s.highestVoteRound > 0 {
		voted = s.highestVoteRound - 1
	}
	if round <= max(voted, qcRound) {
		return false
	}
	return consecutive(round, qcRound) || (tc != nil && consecutive(round, tc.Round))
}

// commitStateIDCandidate is the 2-chain commit rule. A vote for a block whose
// round directly follows its parent's carries the parent's speculated state,
// so the quorum that certifies this block also certifies that commit. A gap in
// rounds commits nothing, which is the zero hash.
func (s *Safety) commitStateIDCandidate(blockRound Round, qc *QC) Hash {
	if !consecutive(blockRound, qc.Round()) {
		return Hash{}
	}
	state, ok := s.ledger.PendingState(qc.VoteInfo.ID)
	if !ok {
		return Hash{}
	}
	return state
}

// MakeVote returns this replica's vote for b, or nil if the safety rules
// refuse it. The counters move only on the path that produces a vote.
func (s *Safety) MakeVote(b *Block, lastTC *TC) *VoteMsg {
	qcRound := b.QC.Round()
	if !s.validSignatures(b.QC, lastTC) || !s.safeToVote(b.Round, qcRound, lastTC) {
		return nil
	}
	// The paper puts this lookup inside the vote and would sign a bottom
	// execution state when it fails. Declining instead: a vote is a claim
	// about an execution result, and a replica that could not execute the
	// block — because it never saw an ancestor, and the paper has no
	// block-sync — has no result to claim.
	exec, ok := s.ledger.PendingState(b.ID())
	if !ok {
		s.declinedMissingAncestor++
		return nil
	}

	s.updateHighestQCRound(qcRound)     // protect the round we are endorsing
	s.increaseHighestVoteRound(b.Round) // never vote in this round again

	voteInfo := VoteInfo{
		ID:          b.ID(),
		Round:       b.Round,
		ParentID:    b.QC.VoteInfo.ID,
		ParentRound: qcRound,
		ExecStateID: exec,
	}
	commit := LedgerCommitInfo{
		CommitStateID: s.commitStateIDCandidate(b.Round, b.QC),
		VoteInfoHash:  VoteInfoHash(voteInfo),
	}
	sig, err := s.crypto.Sign(LedgerCommitDigest(commit))
	if err != nil {
		return nil
	}
	return &VoteMsg{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		HighCommitQC:     s.tree.HighCommitQC(),
		Sender:           s.id,
		Sig:              sig,
	}
}

// MakeTimeout returns this replica's timeout for round, or nil if the safety
// rules refuse it. Timing out burns the round for voting too: the counter is
// raised before the message goes out.
func (s *Safety) MakeTimeout(round Round, highQC *QC, lastTC *TC) *TimeoutInfo {
	qcRound := highQC.Round()
	if !s.validSignatures(highQC, lastTC) || !s.safeToTimeout(round, qcRound, lastTC) {
		return nil
	}
	s.increaseHighestVoteRound(round)
	sig, err := s.crypto.Sign(TimeoutDigest(round, qcRound))
	if err != nil {
		return nil
	}
	return &TimeoutInfo{Round: round, HighQC: highQC, Sender: s.id, Sig: sig}
}

// validSignatures re-checks everything a vote will be built over. The rest of
// the replica has checked it already; Safety checks again because it is the
// one component assumed to survive the rest being compromised.
func (s *Safety) validSignatures(qc *QC, tc *TC) bool {
	return s.verify.VerifyQC(qc) && s.verify.VerifyTC(tc)
}

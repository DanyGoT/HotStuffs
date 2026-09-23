package diem

// Verifier authenticates inbound messages. It holds no protocol state — every
// check here is a function of the message and the replica set alone — which is
// what lets it run on the network's handler goroutines rather than on the
// consensus goroutine.
//
// One check package hotstuff's verifier makes cannot live here. That one reads
// the leader of a view straight off the view number; DiemBFT's
// LeaderElection.GetLeader (3.7) has a reputation path keyed on the committed
// blocks, so a round's leader is a function of protocol state. The leader check
// therefore stays where the paper puts it, inside process_proposal_msg.
type Verifier struct {
	crypto Crypto
	quorum int
}

// NewVerifier builds a Verifier over the given Crypto and quorum size.
func NewVerifier(crypto Crypto, quorum int) *Verifier {
	return &Verifier{crypto: crypto, quorum: quorum}
}

// VerifyQC reports whether qc carries a quorum over the ledger commit info it
// claims, whether that info binds the VoteInfo it ships with, and whether the
// author it names signed the signature set. Without the second check a
// forwarder could swap in a different VoteInfo behind an otherwise valid
// quorum; without the third, Author is a name a Byzantine aggregator writes
// freely.
func (v *Verifier) VerifyQC(qc *QC) bool {
	if qc == nil {
		return false
	}
	if qc.Round() == 0 {
		// Genesis is trusted, not certified: every replica hardcodes it, so it
		// carries neither a quorum nor an author signature.
		return qc.VoteInfo.ID == genesisBlock.ID()
	}
	if VoteInfoHash(qc.VoteInfo) != qc.LedgerCommitInfo.VoteInfoHash {
		return false
	}
	if !v.verifyCert(LedgerCommitDigest(qc.LedgerCommitInfo), qc.Signatures) {
		return false
	}
	// The author signature is the paper's author_signature <- sign_u(signatures)
	// (3.3, process_vote). It adds nothing to the quorum's authority; it binds
	// this particular choice of signature set to the replica that chose it,
	// which is what makes an aggregator that hands out two quorums over one vote
	// attributable — the block id covers the set, so the two are different
	// blocks.
	return qc.AuthorSig.Signer == qc.Author &&
		v.crypto.Verify(qcSigsDigest(qc.Signatures), qc.AuthorSig)
}

// verifyCert checks a certificate's signature set is canonical — signer IDs
// strictly increasing, so no duplicates, no padding and one wire form per
// certificate — and that it carries a quorum of valid signatures. The order
// matters beyond tidiness here: a block id covers its parent certificate's
// signature slice byte for byte (blockID), so one quorum left unordered is one
// quorum's worth of distinct valid block ids.
func (v *Verifier) verifyCert(msg Hash, sigs []Signature) bool {
	for i := 1; i < len(sigs); i++ {
		if sigs[i-1].Signer >= sigs[i].Signer {
			return false
		}
	}
	return v.crypto.VerifyQuorum(msg, sigs)
}

// VerifyTC reports whether tc carries a quorum of signers in canonical order,
// each having signed tc's round paired with its own reported high_qc round. A
// nil TC is valid: whether one was required is a well-formedness question,
// decided before a message reaches here.
func (v *Verifier) VerifyTC(tc *TC) bool {
	if tc == nil {
		return true
	}
	// Round 0 is genesis, which no replica ever times out of.
	if tc.Round == 0 {
		return false
	}
	for i, vote := range tc.Votes {
		if i > 0 && tc.Votes[i-1].Sig.Signer >= vote.Sig.Signer {
			return false
		}
		if !v.crypto.Verify(TimeoutDigest(tc.Round, vote.HighQCRound), vote.Sig) {
			return false
		}
	}
	return len(tc.Votes) >= v.quorum
}

// VerifyProposal reports whether p is well formed and validly signed by its
// sender, and whether every certificate it carries holds up. Whether its author
// leads the round is decided in Core; see the type comment.
func (v *Verifier) VerifyProposal(p *ProposalMsg) bool {
	if !p.WellFormed() {
		return false
	}
	// A block must extend a round below its own. The well-formedness rule alone
	// permits any certificate behind a TC, and safeToVote catches the rest only
	// after the pacemaker has advanced and the block has been speculated.
	if p.Block.QC.Round() >= p.Block.Round {
		return false
	}
	if p.Sig.Signer != p.Sender || !v.crypto.Verify(p.Block.ID(), p.Sig) {
		return false
	}
	return v.VerifyQC(p.Block.QC) && v.verifyCommitQC(p.HighCommitQC) && v.VerifyTC(p.LastRoundTC)
}

// VerifyTimeout reports whether m is well formed and validly signed, and
// whether every certificate it carries holds up.
func (v *Verifier) VerifyTimeout(m *TimeoutMsg) bool {
	if !m.WellFormed() {
		return false
	}
	t := m.TmoInfo
	if t.Sig.Signer != t.Sender || !v.crypto.Verify(TimeoutDigest(t.Round, t.HighQC.Round()), t.Sig) {
		return false
	}
	return v.VerifyQC(t.HighQC) && v.verifyCommitQC(m.HighCommitQC) && v.VerifyTC(m.LastRoundTC)
}

// VerifyVote reports whether m is validly signed by its sender.
func (v *Verifier) VerifyVote(m *VoteMsg) bool {
	if m.Sig.Signer != m.Sender {
		return false
	}
	// The vote signs the LedgerCommitInfo alone, so the VoteInfo it ships with
	// is only authenticated through the hash inside it.
	if VoteInfoHash(m.VoteInfo) != m.LedgerCommitInfo.VoteInfoHash {
		return false
	}
	if !v.crypto.Verify(LedgerCommitDigest(m.LedgerCommitInfo), m.Sig) {
		return false
	}
	return v.verifyCommitQC(m.HighCommitQC)
}

// verifyCommitQC accepts an absent commit certificate: it is a catch-up hint,
// not evidence anything depends on.
func (v *Verifier) verifyCommitQC(qc *QC) bool { return qc == nil || v.VerifyQC(qc) }

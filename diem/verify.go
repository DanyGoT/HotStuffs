package diem

import (
	"bytes"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// Verifier authenticates inbound messages. It holds no protocol state — every
// check here is a function of the message and the replica set alone — which is
// what lets it run on the network's handler goroutines rather than on the
// consensus goroutine.
//
// The leader check cannot live here: LeaderElection.GetLeader (3.7) has a
// reputation path keyed on the committed blocks, so a round's leader is a
// function of protocol state. It stays where the paper puts it, inside
// process_proposal_msg.
//
// It is also the edge that makes a wire message safe to read without checks:
// every hash field of a message it accepts is exactly hashLen bytes, and a
// block's id is the one recomputed from its fields, so no digest from the wire
// is trusted before the Verifier has seen it.
type Verifier struct {
	crypto Crypto
	quorum int
}

// NewVerifier builds a Verifier over the given Crypto and quorum size.
func NewVerifier(crypto Crypto, quorum int) *Verifier {
	return &Verifier{crypto: crypto, quorum: quorum}
}

// validHashes reports whether every hash is exactly hashLen bytes.
func validHashes(hs ...[]byte) bool {
	for _, h := range hs {
		if len(h) != hashLen {
			return false
		}
	}
	return true
}

// validVote reports whether the hash fields of a vote's two halves are
// well-sized.
func validVote(v *diempb.VoteInfo, l *diempb.LedgerCommitInfo) bool {
	return validHashes(v.GetId(), v.GetParentId(), v.GetExecStateId(),
		l.GetCommitStateId(), l.GetVoteInfoHash())
}

// VerifyQC reports whether qc carries a quorum over the ledger commit info it
// claims, whether that info binds the VoteInfo it ships with, and whether the
// author it names signed the signature set. Without the second check a
// forwarder could swap in a different VoteInfo behind an otherwise valid
// quorum; without the third, Author is a name a Byzantine aggregator writes
// freely.
func (v *Verifier) VerifyQC(qc *diempb.QuorumCert) bool {
	if qc == nil || !validVote(qc.GetVoteInfo(), qc.GetLedgerCommitInfo()) {
		return false
	}
	if QCRound(qc) == 0 {
		// Genesis is trusted, not certified: every replica hardcodes it, so it
		// carries neither a quorum nor an author signature.
		return bytes.Equal(qc.GetVoteInfo().GetId(), genesisBlock.GetId())
	}
	if !bytes.Equal(VoteInfoHash(qc.GetVoteInfo()), qc.GetLedgerCommitInfo().GetVoteInfoHash()) {
		return false
	}
	if !v.verifyCert(LedgerCommitDigest(qc.GetLedgerCommitInfo()), qc.GetSignatures()) {
		return false
	}
	// The author signature is the paper's author_signature <- sign_u(signatures)
	// (3.3, process_vote). It adds nothing to the quorum's authority; it binds
	// this particular choice of signature set to the replica that chose it,
	// which is what makes an aggregator that hands out two quorums over one vote
	// attributable — the block id covers the set, so the two are different
	// blocks.
	return qc.GetAuthorSig().GetSigner() == qc.GetAuthor() &&
		verifySig(v.crypto, qcSigsDigest(qc.GetSignatures()), qc.GetAuthorSig())
}

// verifyCert checks a certificate's signature set is canonical — signer IDs
// strictly increasing, so no duplicates, no padding and one wire form per
// certificate — and that it carries a quorum of valid signatures. The order
// matters beyond tidiness here: a block id covers its parent certificate's
// signature slice byte for byte (blockID), so one quorum left unordered is one
// quorum's worth of distinct valid block ids.
func (v *Verifier) verifyCert(digest []byte, sigs []*diempb.Signature) bool {
	for i := 1; i < len(sigs); i++ {
		if sigs[i-1].GetSigner() >= sigs[i].GetSigner() {
			return false
		}
	}
	return QuorumReached(v.crypto, v.quorum, digest, sigs)
}

// VerifyTC reports whether tc carries a quorum of signers in canonical order,
// each having signed tc's round paired with its own reported high_qc round. A
// nil TC is valid: whether one was required is a well-formedness question,
// decided before a message reaches here.
func (v *Verifier) VerifyTC(tc *diempb.TimeoutCert) bool {
	if tc == nil {
		return true
	}
	// Round 0 is genesis, which no replica ever times out of.
	if tc.GetRound() == 0 {
		return false
	}
	votes := tc.GetVotes()
	for i, vote := range votes {
		if i > 0 && votes[i-1].GetSig().GetSigner() >= vote.GetSig().GetSigner() {
			return false
		}
		if !verifySig(v.crypto, TimeoutDigest(tc.GetRound(), vote.GetHighQcRound()), vote.GetSig()) {
			return false
		}
	}
	return len(votes) >= v.quorum
}

// VerifyProposal reports whether p is well formed and validly signed by its
// sender, whether its block carries the id its fields hash to, and whether
// every certificate it carries holds up. Whether its author leads the round is
// decided in Core; see the type comment.
func (v *Verifier) VerifyProposal(p *diempb.ProposalMsg) bool {
	if !WellFormedProposal(p) {
		return false
	}
	b := p.GetBlock()
	// A block must extend a round below its own. The well-formedness rule alone
	// permits any certificate behind a TC, and safeToVote catches the rest only
	// after the pacemaker has advanced and the block has been speculated.
	if QCRound(b.GetQc()) >= b.GetRound() {
		return false
	}
	// The one recomputation of the id; the core reads GetId() from here on.
	if !bytes.Equal(blockID(b.GetAuthor(), b.GetRound(), b.GetPayload(), b.GetQc()), b.GetId()) {
		return false
	}
	if p.GetSig().GetSigner() != p.GetSender() || !verifySig(v.crypto, b.GetId(), p.GetSig()) {
		return false
	}
	return v.VerifyQC(b.GetQc()) && v.verifyCommitQC(p.GetHighCommitQc()) && v.VerifyTC(p.GetLastRoundTc())
}

// VerifyTimeout reports whether m is well formed and validly signed, and
// whether every certificate it carries holds up.
func (v *Verifier) VerifyTimeout(m *diempb.TimeoutMsg) bool {
	if !WellFormedTimeout(m) {
		return false
	}
	t := m.GetTmoInfo()
	if t.GetSig().GetSigner() != t.GetSender() ||
		!verifySig(v.crypto, TimeoutDigest(t.GetRound(), QCRound(t.GetHighQc())), t.GetSig()) {
		return false
	}
	return v.VerifyQC(t.GetHighQc()) && v.verifyCommitQC(m.GetHighCommitQc()) && v.VerifyTC(m.GetLastRoundTc())
}

// VerifyVote reports whether m is validly signed by its sender.
func (v *Verifier) VerifyVote(m *diempb.VoteMsg) bool {
	if m.GetSig().GetSigner() != m.GetSender() || !validVote(m.GetVoteInfo(), m.GetLedgerCommitInfo()) {
		return false
	}
	// The vote signs the LedgerCommitInfo alone, so the VoteInfo it ships with
	// is only authenticated through the hash inside it.
	if !bytes.Equal(VoteInfoHash(m.GetVoteInfo()), m.GetLedgerCommitInfo().GetVoteInfoHash()) {
		return false
	}
	if !verifySig(v.crypto, LedgerCommitDigest(m.GetLedgerCommitInfo()), m.GetSig()) {
		return false
	}
	return v.verifyCommitQC(m.GetHighCommitQc())
}

// verifyCommitQC accepts an absent commit certificate: it is a catch-up hint,
// not evidence anything depends on.
func (v *Verifier) verifyCommitQC(qc *diempb.QuorumCert) bool { return qc == nil || v.VerifyQC(qc) }

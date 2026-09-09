package hotstuff

// Verifier authenticates inbound messages. It holds no protocol state — every
// check here is a function of the message and the replica set alone — which is
// what lets it run on the Gorums handler goroutines rather than on the
// consensus goroutine.
type Verifier struct {
	crypto Crypto
	leader LeaderRotation
}

// NewVerifier builds a Verifier over the given Crypto and leader schedule.
func NewVerifier(c Crypto, leader LeaderRotation) *Verifier {
	return &Verifier{crypto: c, leader: leader}
}

// verifyCert checks a certificate's signature set is canonical — signer IDs
// strictly increasing, so no duplicates and one wire form per certificate —
// and that it carries a quorum of valid signatures.
func (v *Verifier) verifyCert(msg Hash, sigs []Signature) bool {
	for i := 1; i < len(sigs); i++ {
		if sigs[i-1].Signer >= sigs[i].Signer {
			return false
		}
	}
	return v.crypto.VerifyQuorum(msg, sigs)
}

// VerifyQC reports whether qc is a valid quorum certificate: the genesis QC
// by convention, or a certificate over a quorum of votes.
func (v *Verifier) VerifyQC(qc QuorumCert) bool {
	if qc.View == 0 {
		// Genesis QC convention: the only view-0 QC is the fixed value the
		// first real block carries; anything else at view 0 is a forgery.
		return qc.BlockHash == GenesisHash() && len(qc.Sigs) == 0
	}
	return v.verifyCert(VoteDigest(qc.View, qc.BlockHash), qc.Sigs)
}

// VerifyTC reports whether tc is a valid timeout certificate.
func (v *Verifier) VerifyTC(tc TimeoutCert) bool {
	if tc.View == 0 {
		return false
	}
	return v.verifyCert(TimeoutDigest(tc.View), tc.Sigs)
}

// VerifyVote reports whether cert is a validly signed vote.
func (v *Verifier) VerifyVote(cert PartialCert) bool {
	if cert.View == 0 {
		return false
	}
	// An unknown signer fails verification, so there is no separate range check.
	return v.crypto.Verify(VoteDigest(cert.View, cert.BlockHash), cert.Sig)
}

// VerifyTimeout reports whether m is a validly signed timeout carrying a
// valid high QC.
func (v *Verifier) VerifyTimeout(m TimeoutMsg) bool {
	if m.View == 0 {
		return false
	}
	if !v.VerifyQC(m.HighQC) {
		return false
	}
	return v.crypto.Verify(TimeoutDigest(m.View), m.Sig)
}

// VerifyProposal reports whether p is a validly signed, validly justified
// proposal from the leader of its block's view.
func (v *Verifier) VerifyProposal(p Proposal) bool {
	if p.Block == nil || p.Block.View() == 0 {
		return false
	}
	if p.Block.Proposer() != v.leader(p.Block.View()) {
		return false
	}
	if p.Sig.Signer != p.Block.Proposer() {
		return false
	}
	if p.Block.QC().View >= p.Block.View() {
		return false
	}
	if !v.VerifyQC(p.Block.QC()) {
		return false
	}
	// Entry to the block's view must be justified, or a Byzantine leader could
	// drag replicas to an arbitrary view: either a TC for the immediately
	// preceding view, or the block's own QC already sits at that view. This
	// is the whole reason a TimeoutCert exists rather than the paper's
	// NewView message.
	if p.TC != nil {
		if p.TC.View+1 != p.Block.View() || !v.VerifyTC(*p.TC) {
			return false
		}
	} else if p.Block.QC().View+1 != p.Block.View() {
		return false
	}
	return v.crypto.Verify(p.Block.Hash(), p.Sig)
}

// QuorumReached counts distinct signers whose signature verifies and reports
// whether that reaches the quorum for n replicas. It is the shared body of
// Crypto.VerifyQuorum; an implementation that batch-verifies will not use it.
func QuorumReached(n int, msg Hash, sigs []Signature, verify func(Hash, Signature) bool) bool {
	quorum := QuorumSize(n)
	seen := make(map[ID]bool, len(sigs))
	for _, sig := range sigs {
		if seen[sig.Signer] || !verify(msg, sig) {
			continue
		}
		seen[sig.Signer] = true
		if len(seen) >= quorum {
			return true
		}
	}
	return false
}

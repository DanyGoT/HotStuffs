package diem

import "github.com/DanyGoT/HotStuffs/proto/diempb"

// Faulty is the number of Byzantine replicas a group of n tolerates.
func Faulty(n int) int { return (n - 1) / 3 }

// QuorumSize is the number of votes a certificate needs: ceil((n+f+1)/2).
func QuorumSize(n int) int { return (n + Faulty(n) + 2) / 2 }

// verifySig reports whether sig is a valid signature over digest by the signer
// it names.
func verifySig(c Crypto, digest []byte, sig *diempb.Signature) bool {
	return c.Verify(sig.GetSigner(), digest, sig.GetSig())
}

// sign signs digest and names id as the signer.
func sign(c Crypto, id uint32, digest []byte) (*diempb.Signature, error) {
	sig, err := c.Sign(digest)
	if err != nil {
		return nil, err
	}
	return diempb.Signature_builder{Signer: id, Sig: sig}.Build(), nil
}

// QuorumReached counts distinct signers whose signature over digest verifies
// and reports whether that reaches quorum.
func QuorumReached(c Crypto, quorum int, digest []byte, sigs []*diempb.Signature) bool {
	seen := make(map[uint32]bool, len(sigs))
	for _, sig := range sigs {
		if seen[sig.GetSigner()] || !verifySig(c, digest, sig) {
			continue
		}
		seen[sig.GetSigner()] = true
		if len(seen) >= quorum {
			return true
		}
	}
	return false
}

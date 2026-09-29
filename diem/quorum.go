package diem

// Faulty is the number of Byzantine replicas a group of n tolerates.
func Faulty(n int) int { return (n - 1) / 3 }

// QuorumSize is the number of votes a certificate needs: ceil((n+f+1)/2).
func QuorumSize(n int) int { return (n + Faulty(n) + 2) / 2 }

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

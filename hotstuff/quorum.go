// Package hotstuff holds the protocol domain: types, hashing, quorum math, the
// sealed event set, every seam the implementation plugs into, and the pure
// message verifiers. It imports the standard library only.
package hotstuff

// Faulty is the number of Byzantine replicas a group of n tolerates.
func Faulty(n int) int { return (n - 1) / 3 }

// QuorumSize is the number of votes a quorum certificate needs: ceil((n+f+1)/2).
func QuorumSize(n int) int { return (n + Faulty(n) + 2) / 2 }

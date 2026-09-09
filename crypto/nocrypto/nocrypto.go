// Package nocrypto implements hotstuff.Crypto as a deterministic stand-in with
// no key material.
package nocrypto

import (
	"bytes"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Signer is a stand-in for real crypto in the deterministic harness: a
// signature is the signed digest itself, so a wrong-digest bug still fails,
// but there is no key material and no randomness. Never use it in production.
type Signer struct {
	id hotstuff.ID
	n  int
}

// New returns a Signer for replica id in a group of n.
func New(id hotstuff.ID, n int) *Signer {
	return &Signer{id: id, n: n}
}

// Sign returns the digest itself, tagged with this replica's ID.
func (s *Signer) Sign(msg hotstuff.Hash) (hotstuff.Signature, error) {
	data := make([]byte, len(msg))
	copy(data, msg[:])
	return hotstuff.Signature{Signer: s.id, Data: data}, nil
}

// Verify checks that sig names a replica in 1..n and carries msg itself.
func (s *Signer) Verify(msg hotstuff.Hash, sig hotstuff.Signature) bool {
	if sig.Signer < 1 || uint64(sig.Signer) > uint64(s.n) {
		return false
	}
	return bytes.Equal(sig.Data, msg[:])
}

// VerifyQuorum reports whether sigs holds a quorum of distinct valid
// signatures over msg.
func (s *Signer) VerifyQuorum(msg hotstuff.Hash, sigs []hotstuff.Signature) bool {
	return hotstuff.QuorumReached(s.n, msg, sigs, s.Verify)
}

var _ hotstuff.Crypto = (*Signer)(nil)

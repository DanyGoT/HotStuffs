// Package crypto implements hotstuff.Crypto with ECDSA over P-256.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Signer signs with this replica's private key and verifies against the
// registered public key of the claimed signer.
type Signer struct {
	id   hotstuff.ID
	key  *ecdsa.PrivateKey
	keys map[hotstuff.ID]*ecdsa.PublicKey
}

// New returns a Signer for replica id. keys holds the public key of every
// replica, itself included; its size is the replica count, which is what fixes
// the quorum size.
func New(id hotstuff.ID, key *ecdsa.PrivateKey, keys map[hotstuff.ID]*ecdsa.PublicKey) *Signer {
	return &Signer{id: id, key: key, keys: keys}
}

// Sign signs msg with this replica's private key.
func (s *Signer) Sign(msg hotstuff.Hash) (hotstuff.Signature, error) {
	der, err := ecdsa.SignASN1(rand.Reader, s.key, msg[:])
	if err != nil {
		return hotstuff.Signature{}, err
	}
	return hotstuff.Signature{Signer: s.id, Data: der}, nil
}

// Verify checks sig against the registered public key of its claimed signer.
func (s *Signer) Verify(msg hotstuff.Hash, sig hotstuff.Signature) bool {
	pub, ok := s.keys[sig.Signer]
	if !ok {
		return false
	}
	return ecdsa.VerifyASN1(pub, msg[:], sig.Data)
}

// VerifyQuorum reports whether sigs holds a quorum of distinct valid
// signatures over msg.
func (s *Signer) VerifyQuorum(msg hotstuff.Hash, sigs []hotstuff.Signature) bool {
	return hotstuff.QuorumReached(len(s.keys), msg, sigs, s.Verify)
}

// GenerateKeys returns a private key per replica for IDs 1..n, and the public
// key map they share. For -local runs and tests; a real deployment
// distributes keys out of band.
func GenerateKeys(n int) (map[hotstuff.ID]*ecdsa.PrivateKey, map[hotstuff.ID]*ecdsa.PublicKey, error) {
	privs := make(map[hotstuff.ID]*ecdsa.PrivateKey, n)
	pubs := make(map[hotstuff.ID]*ecdsa.PublicKey, n)
	for i := 1; i <= n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		id := hotstuff.ID(i)
		privs[id] = key
		pubs[id] = &key.PublicKey
	}
	return privs, pubs, nil
}

var _ hotstuff.Crypto = (*Signer)(nil)

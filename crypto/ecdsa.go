// Package crypto implements diem.Crypto with ECDSA over P-256.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/DanyGoT/HotStuffs/diem"
)

// Signer signs with this replica's private key and verifies against the
// registered public key of the claimed signer.
type Signer struct {
	id   diem.ID
	key  *ecdsa.PrivateKey
	keys map[diem.ID]*ecdsa.PublicKey
}

// New returns a Signer for replica id. keys holds the public key of every
// replica, itself included; its size is the replica count, which is what fixes
// the quorum size.
func New(id diem.ID, key *ecdsa.PrivateKey, keys map[diem.ID]*ecdsa.PublicKey) *Signer {
	return &Signer{id: id, key: key, keys: keys}
}

// Sign signs msg with this replica's private key.
func (s *Signer) Sign(msg diem.Hash) (diem.Signature, error) {
	der, err := ecdsa.SignASN1(rand.Reader, s.key, msg[:])
	if err != nil {
		return diem.Signature{}, err
	}
	return diem.Signature{Signer: s.id, Data: der}, nil
}

// Verify checks sig against the registered public key of its claimed signer.
func (s *Signer) Verify(msg diem.Hash, sig diem.Signature) bool {
	pub, ok := s.keys[sig.Signer]
	if !ok {
		return false
	}
	return ecdsa.VerifyASN1(pub, msg[:], sig.Data)
}

// VerifyQuorum reports whether sigs holds a quorum of distinct valid
// signatures over msg.
func (s *Signer) VerifyQuorum(msg diem.Hash, sigs []diem.Signature) bool {
	return diem.QuorumReached(len(s.keys), msg, sigs, s.Verify)
}

// GenerateKeys returns a private key per replica for IDs 1..n, and the public
// key map they share. For -local runs and tests; a real deployment
// distributes keys out of band.
func GenerateKeys(n int) (map[diem.ID]*ecdsa.PrivateKey, map[diem.ID]*ecdsa.PublicKey, error) {
	privs := make(map[diem.ID]*ecdsa.PrivateKey, n)
	pubs := make(map[diem.ID]*ecdsa.PublicKey, n)
	for i := 1; i <= n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		id := diem.ID(i)
		privs[id] = key
		pubs[id] = &key.PublicKey
	}
	return privs, pubs, nil
}

var _ diem.Crypto = (*Signer)(nil)

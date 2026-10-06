// Package crypto implements ECDSA over P-256 signing and verification of
// digests, which is what diem.Crypto asks for. It depends on the standard
// library alone.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Signer signs with this replica's private key and verifies against the
// registered public key of the claimed signer.
type Signer struct {
	key  *ecdsa.PrivateKey
	keys map[uint32]*ecdsa.PublicKey
}

// New returns a Signer holding key. keys holds the public key of every
// replica, this one included.
func New(key *ecdsa.PrivateKey, keys map[uint32]*ecdsa.PublicKey) *Signer {
	return &Signer{key: key, keys: keys}
}

// Sign signs digest with this replica's private key and returns the ASN.1 DER
// signature.
func (s *Signer) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// Verify checks sig over digest against the registered public key of signer.
func (s *Signer) Verify(signer uint32, digest, sig []byte) bool {
	pub, ok := s.keys[signer]
	if !ok {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// GenerateKeys returns a private key per replica for IDs 1..n, and the public
// key map they share. For -local runs and tests; a real deployment
// distributes keys out of band.
func GenerateKeys(n int) (map[uint32]*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	privs := make(map[uint32]*ecdsa.PrivateKey, n)
	pubs := make(map[uint32]*ecdsa.PublicKey, n)
	for i := 1; i <= n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		id := uint32(i)
		privs[id] = key
		pubs[id] = &key.PublicKey
	}
	return privs, pubs, nil
}

// SeededKeys is GenerateKeys without randomness: replica id's private key is
// derived from SHA-256 of id, so every process computes the same set with no
// key files. Anyone can derive them; for benchmarks and tests only.
func SeededKeys(n int) (map[uint32]*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	privs := make(map[uint32]*ecdsa.PrivateKey, n)
	pubs := make(map[uint32]*ecdsa.PublicKey, n)
	for i := 1; i <= n; i++ {
		id := uint32(i)
		key, err := seededKey(id)
		if err != nil {
			return nil, nil, err
		}
		privs[id] = key
		pubs[id] = &key.PublicKey
	}
	return privs, pubs, nil
}

// seededKey hashes id with a counter until the digest is a valid P-256 scalar,
// which the first attempt almost always is.
func seededKey(id uint32) (*ecdsa.PrivateKey, error) {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:4], uint32(id))
	for ctr := range uint32(16) {
		binary.BigEndian.PutUint32(buf[4:], ctr)
		d := sha256.Sum256(buf[:])
		if key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:]); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("replica %d: no valid seeded key", id)
}

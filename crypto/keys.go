package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// Key material is distributed out of band, as PEM files in one directory:
// <id>.key holds replica id's private key and <id>.pub its public key. This is
// the smallest thing that lets a cluster start; it is not a key management
// story, and the report says so.

// WriteKeys writes every replica's key pair into dir as PEM.
func WriteKeys(dir string, privs map[hotstuff.ID]*ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for id, key := range privs {
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("replica %d private key: %w", id, err)
		}
		if err := writePEM(filepath.Join(dir, fmt.Sprintf("%d.key", id)), "EC PRIVATE KEY", der, 0o600); err != nil {
			return err
		}
		der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return fmt.Errorf("replica %d public key: %w", id, err)
		}
		if err := writePEM(filepath.Join(dir, fmt.Sprintf("%d.pub", id)), "PUBLIC KEY", der, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ReadKeys reads replica id's private key and every replica's public key from
// dir. The public keys found there define the replica set, and so the quorum.
func ReadKeys(dir string, id hotstuff.ID) (*ecdsa.PrivateKey, map[hotstuff.ID]*ecdsa.PublicKey, error) {
	der, err := readPEM(filepath.Join(dir, fmt.Sprintf("%d.key", id)), "EC PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("replica %d private key: %w", id, err)
	}

	names, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, nil, err
	}
	pubs := make(map[hotstuff.ID]*ecdsa.PublicKey, len(names))
	for _, name := range names {
		base := filepath.Base(name)
		n, err := strconv.ParseUint(base[:len(base)-len(".pub")], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("public key %q: name is not a replica ID", base)
		}
		der, err := readPEM(name, "PUBLIC KEY")
		if err != nil {
			return nil, nil, err
		}
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", base, err)
		}
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("%s: not an ECDSA public key", base)
		}
		pubs[hotstuff.ID(n)] = pub
	}
	// The public keys found here define the replica set, and so the quorum
	// and the leader rotation. They must therefore be exactly 1..n: a stale
	// <id>.pub left in the directory would otherwise change both, silently,
	// and only on the replicas that can see the file.
	if len(pubs) == 0 {
		return nil, nil, fmt.Errorf("no public keys in %s", dir)
	}
	for i := hotstuff.ID(1); int(i) <= len(pubs); i++ {
		if pubs[i] == nil {
			return nil, nil, fmt.Errorf("%s holds %d public keys but not %d.pub: they must be 1..%d", dir, len(pubs), i, len(pubs))
		}
	}
	return priv, pubs, nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, b, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readPEM(path, blockType string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != blockType {
		return nil, fmt.Errorf("%s: not a %s PEM block", path, blockType)
	}
	return block.Bytes, nil
}

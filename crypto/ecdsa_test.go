package crypto

import (
	"bytes"
	"testing"
)

// fixedHash returns 32 identical bytes, a distinguishable stand-in wherever a
// test just needs some digest.
func fixedHash(b byte) []byte {
	return bytes.Repeat([]byte{b}, 32)
}

// newSigners generates keys for n replicas and returns one Signer per ID.
func newSigners(t *testing.T, n int) map[uint32]*Signer {
	t.Helper()
	privs, pubs, err := GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	signers := make(map[uint32]*Signer, n)
	for id, key := range privs {
		signers[id] = New(key, pubs)
	}
	return signers
}

func TestGenerateKeys(t *testing.T) {
	const n = 4
	privs, pubs, err := GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if len(privs) != n || len(pubs) != n {
		t.Fatalf("GenerateKeys(%d) = %d privs, %d pubs, want %d each", n, len(privs), len(pubs), n)
	}
	for i := 1; i <= n; i++ {
		id := uint32(i)
		priv, ok := privs[id]
		if !ok {
			t.Fatalf("missing private key for ID %d", id)
		}
		pub, ok := pubs[id]
		if !ok {
			t.Fatalf("missing public key for ID %d", id)
		}
		if !pub.Equal(&priv.PublicKey) {
			t.Errorf("ID %d: public key does not match its private key", id)
		}
	}
}

func TestSeededKeysAgreeAcrossCalls(t *testing.T) {
	const n = 4
	privsA, _, err := SeededKeys(n)
	if err != nil {
		t.Fatalf("SeededKeys: %v", err)
	}
	_, pubsB, err := SeededKeys(n)
	if err != nil {
		t.Fatalf("SeededKeys: %v", err)
	}
	msg := fixedHash(1)
	for id, key := range privsA {
		sig, err := New(key, pubsB).Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		// A separate process verifies with its own call's public keys.
		if !New(nil, pubsB).Verify(id, msg, sig) {
			t.Errorf("ID %d: signature from one call does not verify against another's keys", id)
		}
		for other, pub := range pubsB {
			if other != id && pub.Equal(&key.PublicKey) {
				t.Errorf("IDs %d and %d share a key", id, other)
			}
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	const n = 4
	signers := newSigners(t, n)
	msg := fixedHash(1)
	for i := 1; i <= n; i++ {
		id := uint32(i)
		sig, err := signers[id].Sign(msg)
		if err != nil {
			t.Fatalf("ID %d: Sign: %v", id, err)
		}
		if !signers[id].Verify(id, msg, sig) {
			t.Errorf("ID %d: Verify() = false, want true", id)
		}
	}
}

func TestVerify(t *testing.T) {
	const n = 4
	signers := newSigners(t, n)
	msg := fixedHash(1)
	otherMsg := fixedHash(2)

	sig1, err := signers[1].Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := append([]byte{}, sig1...)
	tampered[0] ^= 0xFF

	tests := []struct {
		name   string
		signer uint32
		sig    []byte
		msg    []byte
		want   bool
	}{
		{"valid", 1, sig1, msg, true},
		{"claimed as another replica", 2, sig1, msg, false},
		{"unregistered signer", n + 1, sig1, msg, false},
		{"tampered data", 1, tampered, msg, false},
		{"empty data", 1, []byte{}, msg, false},
		{"nil data", 1, nil, msg, false},
		{"different digest", 1, sig1, otherMsg, false},
	}
	for _, tt := range tests {
		if got := signers[1].Verify(tt.signer, tt.msg, tt.sig); got != tt.want {
			t.Errorf("%s: Verify() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSignIsRandomized(t *testing.T) {
	signers := newSigners(t, 1)
	msg := fixedHash(9)

	sig1, err := signers[1].Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig2, err := signers[1].Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if bytes.Equal(sig1, sig2) {
		t.Error("two Sign calls over the same digest produced identical DER bytes")
	}
	if !signers[1].Verify(1, msg, sig1) || !signers[1].Verify(1, msg, sig2) {
		t.Error("both signatures should verify")
	}
}

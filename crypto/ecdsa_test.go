package crypto

import (
	"bytes"
	"testing"

	"github.com/DanyGoT/HotStuffs/diem"
)

// fixedHash returns a Hash of 32 identical bytes, a distinguishable stand-in
// wherever a test just needs some digest.
func fixedHash(b byte) diem.Hash {
	var h diem.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// newSigners generates keys for n replicas and returns one Signer per ID.
func newSigners(t *testing.T, n int) map[diem.ID]*Signer {
	t.Helper()
	privs, pubs, err := GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	signers := make(map[diem.ID]*Signer, n)
	for id, key := range privs {
		signers[id] = New(id, key, pubs)
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
		id := diem.ID(i)
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

func TestSignVerifyRoundTrip(t *testing.T) {
	const n = 4
	signers := newSigners(t, n)
	msg := fixedHash(1)
	for i := 1; i <= n; i++ {
		id := diem.ID(i)
		sig, err := signers[id].Sign(msg)
		if err != nil {
			t.Fatalf("ID %d: Sign: %v", id, err)
		}
		if sig.Signer != id {
			t.Errorf("ID %d: sig.Signer = %d, want %d", id, sig.Signer, id)
		}
		if !signers[id].Verify(msg, sig) {
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

	tampered := diem.Signature{Signer: sig1.Signer, Data: append([]byte{}, sig1.Data...)}
	tampered.Data[0] ^= 0xFF

	tests := []struct {
		name string
		sig  diem.Signature
		msg  diem.Hash
		want bool
	}{
		{"valid", sig1, msg, true},
		{"rewritten to another replica's ID", diem.Signature{Signer: 2, Data: sig1.Data}, msg, false},
		{"unregistered signer", diem.Signature{Signer: diem.ID(n + 1), Data: sig1.Data}, msg, false},
		{"tampered data", tampered, msg, false},
		{"empty data", diem.Signature{Signer: 1, Data: []byte{}}, msg, false},
		{"nil data", diem.Signature{Signer: 1, Data: nil}, msg, false},
		{"different digest", sig1, otherMsg, false},
	}
	for _, tt := range tests {
		if got := signers[1].Verify(tt.msg, tt.sig); got != tt.want {
			t.Errorf("%s: Verify() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestVerifyQuorum(t *testing.T) {
	const n = 4
	signers := newSigners(t, n)
	msg := fixedHash(3)
	quorum := diem.QuorumSize(n)

	sign := func(id diem.ID) diem.Signature {
		t.Helper()
		sig, err := signers[id].Sign(msg)
		if err != nil {
			t.Fatalf("ID %d: Sign: %v", id, err)
		}
		return sig
	}

	full := make([]diem.Signature, quorum)
	for i := range full {
		full[i] = sign(diem.ID(i + 1))
	}
	// Registered but never signed with: a malformed DER blob under a real ID.
	garbage := diem.Signature{Signer: diem.ID(quorum + 1), Data: []byte("not a signature")}

	tests := []struct {
		name string
		sigs []diem.Signature
		want bool
	}{
		{"exactly quorum distinct", full, true},
		{"quorum-1", full[:quorum-1], false},
		{"duplicate signer counted once", append(append([]diem.Signature{}, full[:quorum-1]...), full[0]), false},
		{"quorum plus one garbage signature", append([]diem.Signature{garbage}, full...), true},
	}
	for _, tt := range tests {
		if got := signers[1].VerifyQuorum(msg, tt.sigs); got != tt.want {
			t.Errorf("%s: VerifyQuorum() = %v, want %v", tt.name, got, tt.want)
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
	if bytes.Equal(sig1.Data, sig2.Data) {
		t.Error("two Sign calls over the same digest produced identical DER bytes")
	}
	if !signers[1].Verify(msg, sig1) || !signers[1].Verify(msg, sig2) {
		t.Error("both signatures should verify")
	}
}

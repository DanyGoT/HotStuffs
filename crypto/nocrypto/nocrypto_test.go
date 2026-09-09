package nocrypto

import (
	"bytes"
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// fixedHash returns a Hash of 32 identical bytes, a distinguishable stand-in
// wherever a test just needs some digest.
func fixedHash(b byte) hotstuff.Hash {
	var h hotstuff.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func TestSignNeverErrorsAndCarriesDigest(t *testing.T) {
	const n = 4
	msg := fixedHash(1)
	for i := 1; i <= n; i++ {
		id := hotstuff.ID(i)
		sig, err := New(id, n).Sign(msg)
		if err != nil {
			t.Fatalf("ID %d: Sign: %v", id, err)
		}
		if sig.Signer != id {
			t.Errorf("ID %d: sig.Signer = %d, want %d", id, sig.Signer, id)
		}
		if !bytes.Equal(sig.Data, msg[:]) {
			t.Errorf("ID %d: sig.Data = %x, want %x", id, sig.Data, msg[:])
		}
	}
}

// TestSignReturnsACopy checks that Sign's returned Data does not alias the
// digest, and that mutating one Sign's Data cannot affect a later Sign of the
// same digest.
func TestSignReturnsACopy(t *testing.T) {
	s := New(1, 4)
	msg := fixedHash(1)

	sig1, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig1.Data[0] ^= 0xFF

	sig2, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(sig2.Data, msg[:]) {
		t.Errorf("mutating a previous Sign's Data changed a later Sign's Data: got %x, want %x", sig2.Data, msg[:])
	}
	if s.Verify(msg, sig1) {
		t.Error("Verify() = true after tampering with sig.Data, want false")
	}
}

func TestVerify(t *testing.T) {
	const n = 4
	s := New(1, n)
	msg := fixedHash(1)
	otherMsg := fixedHash(2)

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tests := []struct {
		name string
		sig  hotstuff.Signature
		msg  hotstuff.Hash
		want bool
	}{
		{"valid", sig, msg, true},
		{"signer 0", hotstuff.Signature{Signer: 0, Data: sig.Data}, msg, false},
		{"signer n+1", hotstuff.Signature{Signer: hotstuff.ID(n + 1), Data: sig.Data}, msg, false},
		// The property that keeps the deterministic harness able to catch a
		// wrong-digest bug: signing the wrong thing must not verify.
		{"different digest", sig, otherMsg, false},
	}
	for _, tt := range tests {
		if got := s.Verify(tt.msg, tt.sig); got != tt.want {
			t.Errorf("%s: Verify() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestVerifyQuorum(t *testing.T) {
	const n = 4
	s := New(1, n)
	msg := fixedHash(3)
	quorum := hotstuff.QuorumSize(n)

	sign := func(id hotstuff.ID) hotstuff.Signature {
		t.Helper()
		sig, err := New(id, n).Sign(msg)
		if err != nil {
			t.Fatalf("ID %d: Sign: %v", id, err)
		}
		return sig
	}

	full := make([]hotstuff.Signature, quorum)
	for i := range full {
		full[i] = sign(hotstuff.ID(i + 1))
	}
	// Registered but signed over the wrong digest.
	wrongDigest := hotstuff.Signature{Signer: hotstuff.ID(quorum + 1), Data: []byte("not the digest")}

	tests := []struct {
		name string
		sigs []hotstuff.Signature
		want bool
	}{
		{"exactly quorum distinct", full, true},
		{"quorum-1", full[:quorum-1], false},
		{"duplicate signer counted once", append(append([]hotstuff.Signature{}, full[:quorum-1]...), full[0]), false},
		{"quorum plus one wrong-digest signature", append([]hotstuff.Signature{wrongDigest}, full...), true},
	}
	for _, tt := range tests {
		if got := s.VerifyQuorum(msg, tt.sigs); got != tt.want {
			t.Errorf("%s: VerifyQuorum() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

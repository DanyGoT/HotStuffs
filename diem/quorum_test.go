package diem

import (
	"testing"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

func TestFaulty(t *testing.T) {
	for n := 1; n <= 31; n++ {
		if got, want := Faulty(n), (n-1)/3; got != want {
			t.Errorf("Faulty(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestQuorumSize(t *testing.T) {
	// n: quorum, for the group sizes n = 3f+1 that the protocol is stated for.
	want := map[int]int{1: 1, 4: 3, 7: 5, 10: 7, 13: 9, 16: 11, 19: 13, 22: 15, 25: 17, 28: 19, 31: 21}
	for n, q := range want {
		if got := QuorumSize(n); got != q {
			t.Errorf("QuorumSize(%d) = %d, want %d", n, got, q)
		}
	}
}

// A quorum must be big enough that two quorums intersect in at least one
// correct replica, and small enough that the n-f correct replicas can form one.
func TestQuorumSizeProperties(t *testing.T) {
	for n := 1; n <= 31; n++ {
		f, q := Faulty(n), QuorumSize(n)
		if 2*q-n <= f {
			t.Errorf("n=%d f=%d q=%d: two quorums intersect in %d replicas, need > %d", n, f, q, 2*q-n, f)
		}
		if q > n-f {
			t.Errorf("n=%d f=%d q=%d: %d correct replicas cannot form a quorum", n, f, q, n-f)
		}
	}
}

// bodyCrypto treats any signature with a non-empty body as valid:
// QuorumReached's own counting logic, not the crypto, is what the table below
// exercises.
type bodyCrypto struct{ Crypto }

func (bodyCrypto) Verify(_ uint32, _, sig []byte) bool { return len(sig) > 0 }

func TestQuorumReached(t *testing.T) {
	valid := func(id uint32) *diempb.Signature {
		return diempb.Signature_builder{Signer: id, Sig: []byte{1}}.Build()
	}
	invalid := func(id uint32) *diempb.Signature { return diempb.Signature_builder{Signer: id}.Build() }
	digest := hashOf()

	sigsOf := func(f func(uint32) *diempb.Signature, from, to int) []*diempb.Signature {
		var sigs []*diempb.Signature
		for i := from; i <= to; i++ {
			sigs = append(sigs, f(uint32(i)))
		}
		return sigs
	}

	for _, n := range []int{4, 7} {
		quorum := QuorumSize(n)
		tests := []struct {
			name string
			sigs []*diempb.Signature
			want bool
		}{
			{"exactly quorum distinct valid", sigsOf(valid, 1, quorum), true},
			{"quorum-1 distinct valid", sigsOf(valid, 1, quorum-1), false},
			{"quorum valid plus some invalid", append(sigsOf(valid, 1, quorum), sigsOf(invalid, quorum+1, quorum+2)...), true},
			{"duplicate signer counted once", append(sigsOf(valid, 1, quorum-1), valid(1)), false},
			{"empty", nil, false},
		}
		for _, tt := range tests {
			if got := QuorumReached(bodyCrypto{}, quorum, digest, tt.sigs); got != tt.want {
				t.Errorf("n=%d %s: QuorumReached() = %v, want %v", n, tt.name, got, tt.want)
			}
		}
	}

	// n = 1 has quorum 1 too, but zero signatures still cannot reach it.
	if QuorumReached(bodyCrypto{}, 1, digest, nil) {
		t.Error("QuorumReached(quorum 1, nil) = true, want false")
	}
}

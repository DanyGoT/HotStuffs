package diem

import "testing"

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

func TestQuorumReached(t *testing.T) {
	// verify treats any non-nil Data as a valid signature; QuorumReached's own
	// counting logic, not the crypto, is what these tables exercise.
	valid := func(id ID) Signature { return Signature{Signer: id, Data: []byte{1}} }
	invalid := func(id ID) Signature { return Signature{Signer: id, Data: nil} }
	verify := func(_ Hash, sig Signature) bool { return sig.Data != nil }
	var msg Hash

	sigsOf := func(f func(ID) Signature, from, to int) []Signature {
		var sigs []Signature
		for i := from; i <= to; i++ {
			sigs = append(sigs, f(ID(i)))
		}
		return sigs
	}

	for _, n := range []int{4, 7} {
		quorum := QuorumSize(n)
		tests := []struct {
			name string
			sigs []Signature
			want bool
		}{
			{"exactly quorum distinct valid", sigsOf(valid, 1, quorum), true},
			{"quorum-1 distinct valid", sigsOf(valid, 1, quorum-1), false},
			{"quorum valid plus some invalid", append(sigsOf(valid, 1, quorum), sigsOf(invalid, quorum+1, quorum+2)...), true},
			{"duplicate signer counted once", append(sigsOf(valid, 1, quorum-1), valid(1)), false},
			{"empty", nil, false},
		}
		for _, tt := range tests {
			if got := QuorumReached(n, msg, tt.sigs, verify); got != tt.want {
				t.Errorf("n=%d %s: QuorumReached() = %v, want %v", n, tt.name, got, tt.want)
			}
		}
	}

	// n = 1 has quorum 1 too, but zero signatures still cannot reach it.
	if QuorumReached(1, msg, nil, verify) {
		t.Error("QuorumReached(1, ..., nil, ...) = true, want false")
	}
}

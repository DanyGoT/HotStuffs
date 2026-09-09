package hotstuff

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

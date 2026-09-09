package hotstuff

import "testing"

func TestRoundRobin(t *testing.T) {
	for _, n := range []int{1, 4, 7} {
		rr := RoundRobin(n)
		var prev ID
		for v := View(0); v < View(3*n); v++ {
			id := rr(v)
			if id < 1 || int(id) > n {
				t.Errorf("n=%d: rr(%d) = %d, want in [1, %d]", n, v, id, n)
			}
			if v > 0 {
				wantNext := prev%ID(n) + 1
				if id != wantNext {
					t.Errorf("n=%d: rr(%d) = %d, want %d after rr(%d) = %d", n, v, id, wantNext, v-1, prev)
				}
			}
			prev = id
		}
	}
}

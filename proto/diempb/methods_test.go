package diempb

import "testing"

func TestHigher(t *testing.T) {
	qc := func(round uint64) *QuorumCert {
		return QuorumCert_builder{VoteInfo: VoteInfo_builder{Round: round}.Build()}.Build()
	}
	a, b, low := qc(2), qc(2), qc(1)

	tests := []struct {
		name      string
		qc, other *QuorumCert
		want      *QuorumCert
	}{
		{"higher receiver", a, low, a},
		{"higher other", low, a, a},
		{"tie keeps other", a, b, b},
		{"nil receiver", nil, low, low},
	}
	for _, tt := range tests {
		if got := tt.qc.Higher(tt.other); got != tt.want {
			t.Errorf("%s: Higher returned round %d at %p, want %p", tt.name, got.Round(), got, tt.want)
		}
	}
}

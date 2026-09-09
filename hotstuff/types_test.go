package hotstuff

import "testing"

func TestSyncInfoView(t *testing.T) {
	tests := []struct {
		name     string
		qcView   View
		tc       *TimeoutCert
		wantView View
	}{
		{"both zero, no TC", 0, nil, 1},
		{"QC only, no TC", 5, nil, 6},
		{"QC and TC equal", 4, &TimeoutCert{View: 4}, 5},
		{"QC ahead of TC", 7, &TimeoutCert{View: 3}, 8},
		{"TC ahead of QC", 3, &TimeoutCert{View: 7}, 8},
		{"both zero, TC present", 0, &TimeoutCert{View: 0}, 1},
	}
	for _, tt := range tests {
		si := SyncInfo{QC: QuorumCert{View: tt.qcView}, TC: tt.tc}
		if got := si.View(); got != tt.wantView {
			t.Errorf("%s: View() = %d, want %d", tt.name, got, tt.wantView)
		}
	}
}

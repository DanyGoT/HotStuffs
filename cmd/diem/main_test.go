package main

import "testing"

// TestAddresses covers what -remotes must not silently accept: a replica's
// position in the list is its ID, so a repeated or empty entry would hand two
// replicas the same identity.
func TestAddresses(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"blank", "  ", nil, false},
		{"plain", "a:1,b:2", []string{"a:1", "b:2"}, false},
		{"whitespace trimmed", " a:1 ,\tb:2\n", []string{"a:1", "b:2"}, false},
		{"duplicate", "a:1,b:2,a:1", nil, true},
		{"duplicate after trimming", "a:1, a:1", nil, true},
		{"empty entry", "a:1,,b:2", nil, true},
		{"trailing comma", "a:1,b:2,", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*remotes = tt.flag
			got, err := addresses()
			if (err != nil) != tt.wantErr {
				t.Fatalf("addresses() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("addresses() = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("addresses()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

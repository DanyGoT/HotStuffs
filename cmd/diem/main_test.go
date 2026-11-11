package main

import (
	"flag"
	"testing"
)

// parse returns the options for args, parsed on a fresh FlagSet.
func parse(t *testing.T, args ...string) (*options, *flag.FlagSet) {
	t.Helper()
	fs := flag.NewFlagSet("diem", flag.ContinueOnError)
	o := newOptions(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return o, fs
}

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
			o, _ := parse(t, "-remotes", tt.flag)
			got, err := o.addresses()
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

// TestReplicaKeysNeedsExplicitSeed pins that public-seed keys are never the
// silent default: without -keys they need -insecure-seeded-keys.
func TestReplicaKeysNeedsExplicitSeed(t *testing.T) {
	o, _ := parse(t)
	if _, _, err := o.replicaKeys(1, 4); err == nil {
		t.Fatal("replicaKeys without -keys or -insecure-seeded-keys succeeded")
	}
	o, _ = parse(t, "-insecure-seeded-keys")
	if _, _, err := o.replicaKeys(1, 4); err != nil {
		t.Fatalf("replicaKeys with -insecure-seeded-keys: %v", err)
	}
}

// TestFaultTarget pins which replica -fault-kill-after stops, and that a
// -fault-replica outside the cluster fails rather than stopping nobody.
func TestFaultTarget(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    uint32
		wantErr bool
	}{
		{"off", nil, 0, false},
		{"off ignores -fault-replica", []string{"-fault-replica=9"}, 0, false},
		{"default", []string{"-fault-kill-after=1s"}, 1, false},
		{"chosen", []string{"-fault-kill-after=1s", "-fault-replica=4"}, 4, false},
		{"zero", []string{"-fault-kill-after=1s", "-fault-replica=0"}, 0, true},
		{"past n", []string{"-fault-kill-after=1s", "-fault-replica=5"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, _ := parse(t, tt.args...)
			got, err := o.faultTarget(4)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("faultTarget(4) = %d, %v; want %d, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// TestSweepFlags pins that every flag benchkit/cmd/sweep passes a node is
// defined; an undefined one stops the binary before it runs.
func TestSweepFlags(t *testing.T) {
	_, fs := parse(t)
	for _, name := range []string{
		"self", "remotes", "benchmarks", "workers", "payload", "time", "output",
		"rate", "interval", "stats-mode", "rate-step", "rate-step-max",
		"stream-mode", "cpuprofile", "memprofile", "verbose",
	} {
		if fs.Lookup(name) == nil {
			t.Errorf("flag -%s is not defined", name)
		}
	}
}

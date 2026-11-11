package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums/benchkit"
)

// chain is a committed log whose blocks have the given ids.
func chain(ids ...string) []*diempb.Block {
	log := make([]*diempb.Block, len(ids))
	for i, id := range ids {
		log[i] = diempb.Block_builder{Id: []byte(id)}.Build()
	}
	return log
}

// TestReport pins that report fails on a fork or on a replica that committed
// nothing, and accepts logs that agree over their common prefix.
func TestReport(t *testing.T) {
	tests := []struct {
		name    string
		logs    [][]*diempb.Block
		wantErr string
	}{
		{"one replica", [][]*diempb.Block{chain("a")}, ""},
		{"equal", [][]*diempb.Block{chain("a", "b"), chain("a", "b")}, ""},
		{"prefixes", [][]*diempb.Block{chain("a", "b", "c"), chain("a"), chain("a", "b")}, ""},
		{"fork", [][]*diempb.Block{chain("a", "b"), chain("a", "b"), chain("a", "x")}, "replicas 1 and 3 disagree at commit 1"},
		{"empty log", [][]*diempb.Block{chain("a"), chain()}, "replica 2 committed no block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sums := make([]summary, len(tt.logs))
			for i, l := range tt.logs {
				sums[i] = summary{id: uint32(i + 1), log: l}
			}
			var out strings.Builder
			err := report(&out, sums)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("report() = %v, want nil", err)
			}
			if tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Fatalf("report() = %v, want %q", err, tt.wantErr)
			}
			if got := strings.Count(out.String(), "replica "); got != len(sums) {
				t.Errorf("report printed %d replica lines, want %d:\n%s", got, len(sums), out.String())
			}
		})
	}
}

// TestWriteResults pins what sweep reads from -output: one replica of a
// four-replica cluster records the cluster size, not its own count, together
// with the run's flags.
func TestWriteResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pb")
	o, _ := parse(t, "-output", path, "-self", "b:2", "-workers", "3", "-payload", "32", "-rate", "100",
		"-send-buffer", "8", "-time", "2s", "-interval", "100ms", "-stats-mode", "hdr")
	res := benchkit.Result_builder{Config: benchkit.RunConfig_builder{}.Build()}.Build()
	if err := o.writeResults(4, []*benchkit.Result{res}); err != nil {
		t.Fatal(err)
	}

	rep, err := benchkit.LoadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetLabel() != "b:2" || len(rep.GetResults()) != 1 {
		t.Fatalf("report label %q with %d results, want \"b:2\" with 1", rep.GetLabel(), len(rep.GetResults()))
	}
	cfg := rep.GetResults()[0].GetConfig()
	for _, c := range []struct {
		field     string
		got, want any
	}{
		{"name", cfg.GetName(), "diem"},
		{"nodes", cfg.GetNumNodes(), int32(4)},
		{"workers", cfg.GetWorkers(), int32(3)},
		{"payload", cfg.GetPayload(), int32(32)},
		{"rate", cfg.GetRate(), int64(100)},
		{"send buffer", cfg.GetSendBuffer(), int32(8)},
		{"duration", cfg.GetDuration(), int64(2 * time.Second)},
		{"interval", cfg.GetInterval(), int64(100 * time.Millisecond)},
		{"stats mode", cfg.GetStatsMode(), benchkit.StatsMode_HDR},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

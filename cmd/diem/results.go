package main

import (
	"bytes"
	"cmp"
	"fmt"
	"io"

	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/DanyGoT/diembft/replica"
	"github.com/relab/gorums/benchkit"
)

// summary is what report needs from one replica after its run.
type summary struct {
	id       uint32
	log      []*diempb.Block
	commands uint64
	declined uint64
	counters diemnet.Counters
}

func summarize(r *replica.Replica) summary {
	return summary{
		id:       r.ID(),
		log:      r.Log(),
		commands: r.Commands(),
		declined: r.DeclinedMissingAncestor(),
		counters: r.Counters(),
	}
}

// report prints each replica's committed depth and checks the logs agree over
// their common prefix, which is the whole point of running the thing.
func report(w io.Writer, sums []summary) error {
	for _, s := range sums {
		_, _ = fmt.Fprintf(w, "replica %d: committed %d (%d commands), dropped %d, declined for a missing ancestor %d, rejected %d\n",
			s.id, len(s.log), s.commands, s.counters.OutboundDropped, s.declined, s.counters.Rejected)
	}
	for i, a := range sums {
		for _, b := range sums[i+1:] {
			for k := range min(len(a.log), len(b.log)) {
				if !bytes.Equal(a.log[k].GetId(), b.log[k].GetId()) {
					return fmt.Errorf("replicas %d and %d disagree at commit %d", a.id, b.id, k)
				}
			}
		}
	}
	if len(sums) > 1 {
		_, _ = fmt.Fprintln(w, "logs agree over their common prefix")
	}
	for _, s := range sums {
		if len(s.log) == 0 {
			return fmt.Errorf("replica %d committed no block", s.id)
		}
	}
	return nil
}

// writeResults writes results to -output, labelled with the run's dimensions
// for a cluster of n replicas, so benchkit/cmd/sweep can collect them.
func (o *options) writeResults(n int, results []*benchkit.Result) error {
	for _, res := range results {
		cfg := res.GetConfig()
		cfg.ApplyDimensions(benchkit.Dimensions{
			Benchmark: "diem", Nodes: n,
			Workers: o.std.Workers, Payload: o.std.Payload, Rate: o.std.Rate,
			SendBuffer: int(o.sendBuffer),
		})
		cfg.SetDuration(int64(o.std.Duration))
		cfg.SetInterval(int64(o.std.Interval))
		cfg.SetStatsMode(o.std.StatsMode)
	}
	label := cmp.Or(o.std.Self, "local")
	return benchkit.WriteLabeledReport(results, label, o.std.Output)
}

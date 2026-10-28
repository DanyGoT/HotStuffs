// Command diem runs one DiemBFT replica, or a whole cluster in a single process
// with -local.
//
// The standard flags come from benchkit.RegisterFlags and -output writes a
// benchkit result file, so benchkit/cmd/sweep can drive this binary across a
// cluster. Standard flags with no meaning for one protocol, such as -benchmarks,
// are accepted and ignored.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"runtime/trace"
	"slices"
	"strings"
	"sync"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/DanyGoT/HotStuffs/replica"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	std = benchkit.RegisterFlags(flag.CommandLine)

	local          = flag.Int("local", 0, "run this many replicas in one process")
	keys           = flag.String("keys", "", "directory holding <id>.key and <id>.pub; required unless -insecure-seeded-keys")
	insecureSeeded = flag.Bool("insecure-seeded-keys", false, "without -keys, derive every replica's keys from a public seed; anyone can sign for any replica")
	genKeys        = flag.Bool("gen-keys", false, "write a key pair per replica into -keys and exit")
	viewDuration   = flag.Duration("view-duration", 0, "base round timeout; 0 picks a default")
)

func main() {
	flag.Parse()
	level := slog.LevelInfo
	if std.Verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if err := run(); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run() error {
	if std.CPUProfile != "" {
		f, err := os.Create(std.CPUProfile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}
	if std.Trace != "" {
		f, err := os.Create(std.Trace)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := trace.Start(f); err != nil {
			return err
		}
		defer trace.Stop()
	}

	switch {
	case *genKeys:
		return writeKeys()
	case *local > 0:
		return runLocal(*local)
	case std.Self != "":
		return runOne()
	}
	return errors.New("nothing to do: pass -local N, or -self with -remotes")
}

func writeKeys() error {
	n := *local
	if n == 0 {
		addrs, err := addresses()
		if err != nil {
			return err
		}
		n = len(addrs)
	}
	if n == 0 || *keys == "" {
		return errors.New("-gen-keys needs -keys and either -local N or -remotes")
	}
	privs, _, err := crypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	if err := crypto.WriteKeys(*keys, privs); err != nil {
		return err
	}
	slog.Info("wrote keys", "dir", *keys, "replicas", n)
	return nil
}

// runLocal runs a whole cluster in one process. gorums.NewLocalServers
// pre-allocates the loopback listeners and numbers the servers 1..n, which is
// what makes this possible at all: WithPeers needs every address before any
// server exists.
func runLocal(n int) error {
	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	srvs, stop, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(dialOptions()...))
	if err != nil {
		return err
	}
	defer stop()

	reps := make([]*replica.Replica, n)
	for i := range n {
		id := uint32(i + 1)
		reps[i] = replica.New(replica.Config{
			ID: id, Key: privs[id], Keys: pubs,
			Transactions: transactions(),
			RoundTimeout: *viewDuration,
			Duration:     std.Duration,
			Server:       srvs[i],
		})
	}
	return runAll(reps)
}

// replicaKeys reads id's keys from -keys. Without it, the seeded set every
// replica computes alike is used only when -insecure-seeded-keys asks for it.
func replicaKeys(id uint32, n int) (*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	if *keys != "" {
		return crypto.ReadKeys(*keys, id)
	}
	if !*insecureSeeded {
		return nil, nil, errors.New("no -keys: pass -keys DIR, or -insecure-seeded-keys to use public-seed keys")
	}
	slog.Warn("using insecure seeded keys")
	privs, pubs, err := crypto.SeededKeys(n)
	if err != nil {
		return nil, nil, err
	}
	return privs[id], pubs, nil
}

// runOne runs this process's single replica. -remotes lists every replica in ID
// order, so a replica's position in that list is its ID.
func runOne() error {
	addrs, err := addresses()
	if err != nil {
		return err
	}
	self := strings.TrimSpace(std.Self)
	idx := slices.Index(addrs, self)
	if idx < 0 {
		return fmt.Errorf("-self %q does not appear in -remotes", self)
	}
	id := uint32(idx + 1)
	priv, pubs, err := replicaKeys(id, len(addrs))
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, addr := range addrs {
		peers[uint32(i+1)] = addr
	}
	return runAll([]*replica.Replica{replica.New(replica.Config{
		ID: id, Peers: peers, Listen: self,
		Key: priv, Keys: pubs,
		Transactions: transactions(),
		RoundTimeout: *viewDuration,
		Duration:     std.Duration,
		DialOptions:  dialOptions(),
	})})
}

// runAll runs every replica for -time from its first round, or until the
// process is interrupted, then reports what each committed.
func runAll(reps []*replica.Replica) error {
	root, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	for i, r := range reps {
		ctx := root
		if std.FaultKillAfter > 0 && i == 0 {
			var kill context.CancelFunc
			ctx, kill = context.WithTimeout(root, std.FaultKillAfter)
			defer kill()
		}
		wg.Go(func() {
			if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				slog.Error("replica stopped", "id", r.ID(), "err", err)
			}
		})
	}
	wg.Wait()
	if err := report(reps); err != nil {
		return err
	}
	if std.Output == "" {
		return nil
	}
	return writeResults(reps)
}

// writeResults writes one benchkit Result per replica to -output, so
// benchkit/cmd/sweep can collect it. An op is a committed block, and its
// latency is propose to commit at the replica that proposed it.
func writeResults(reps []*replica.Replica) error {
	n := *local
	if n == 0 {
		addrs, err := addresses()
		if err != nil {
			return err
		}
		n = len(addrs)
	}
	results := make([]*benchkit.Result, len(reps))
	for i, r := range reps {
		cfg := benchkit.NewRunConfig(benchkit.Dimensions{
			Benchmark: "diem", Nodes: n,
			Workers: std.Workers, Payload: std.Payload, Rate: std.Rate,
		})
		cfg.SetDuration(std.Duration.Nanoseconds())
		ops := uint64(len(r.Log()))
		elapsed := r.Elapsed()
		lats := r.Latencies()
		ns := make([]int64, len(lats))
		for j, l := range lats {
			ns[j] = l.Nanoseconds()
		}
		results[i] = benchkit.Result_builder{
			Config:     cfg,
			TotalOps:   ops,
			TotalTime:  elapsed.Nanoseconds(),
			Throughput: float64(ops) / elapsed.Seconds(),
			Latencies:  ns,
		}.Build()
	}
	label := cmp.Or(std.Self, "local")
	return benchkit.WriteLabeledReport(results, label, std.Output)
}

// report prints each replica's committed depth and checks the logs agree over
// their common prefix, which is the whole point of running the thing.
func report(reps []*replica.Replica) error {
	w := os.Stdout
	logs := make([][]*diempb.Block, len(reps))
	for i, r := range reps {
		logs[i] = r.Log()
		c := r.Counters()
		fmt.Fprintf(w, "replica %d: committed %d (%d commands), dropped %d, declined for a missing ancestor %d, rejected %d, queue high-water %d\n",
			r.ID(), len(logs[i]), r.Commands(), c.OutboundDropped, r.DeclinedMissingAncestor(), c.Rejected, r.QueueHighWater())
	}
	for i := range logs {
		for j := i + 1; j < len(logs); j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if !bytes.Equal(logs[i][k].GetId(), logs[j][k].GetId()) {
					return fmt.Errorf("replicas %d and %d disagree at commit %d", reps[i].ID(), reps[j].ID(), k)
				}
			}
		}
	}
	if len(reps) > 1 {
		fmt.Fprintln(w, "logs agree over their common prefix")
	}
	for i, l := range logs {
		if len(l) == 0 {
			return fmt.Errorf("replica %d committed no block", reps[i].ID())
		}
	}
	return nil
}

// addresses is -remotes as a list, whitespace trimmed. A replica's position in
// it is its ID, so an empty or repeated entry would hand two replicas the same
// identity rather than fail.
func addresses() ([]string, error) {
	if len(std.Remotes) == 1 && strings.TrimSpace(std.Remotes[0]) == "" {
		return nil, nil
	}
	addrs := make([]string, len(std.Remotes))
	seen := make(map[string]bool, len(addrs))
	for i, addr := range std.Remotes {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return nil, fmt.Errorf("-remotes entry %d is empty", i+1)
		}
		if seen[addr] {
			return nil, fmt.Errorf("-remotes lists %q twice; each entry is one replica's ID", addr)
		}
		seen[addr] = true
		addrs[i] = addr
	}
	return addrs, nil
}

// transactions is the leader's payload source; nil proposes empty blocks.
func transactions() func() [][]byte {
	if std.Payload <= 0 {
		return nil
	}
	return replica.NewPayload(std.Payload, std.Workers, std.Rate).Transactions
}

// GORUMS: NewLocalServers and any real dial need explicit transport
// credentials; there is no insecure default.
func dialOptions() []gorums.DialOption {
	return []gorums.DialOption{gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))}
}

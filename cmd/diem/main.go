// Command diem runs one DiemBFT replica, or a whole cluster in a single process
// with -local.
//
// The flag names follow benchkit.StandardFlags and -output writes a benchkit
// result file, so benchkit/cmd/sweep can drive this binary across a cluster.
// Flags the prototype does not act on yet are accepted and ignored rather than
// dropped, so the contract stays whole.
package main

import (
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/replica"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// Acted on.
	local          = flag.Int("local", 0, "run this many replicas in one process")
	self           = flag.String("self", "", "this replica's address, which must appear in -remotes")
	remotes        = flag.String("remotes", "", "comma-separated addresses of every replica, in ID order 1..n")
	keys           = flag.String("keys", "", "directory holding <id>.key and <id>.pub; empty uses insecure seeded keys")
	genKeys        = flag.Bool("gen-keys", false, "write a key pair per replica into -keys and exit")
	payload        = flag.Int("payload", 0, "bytes per command; 0 proposes empty blocks")
	workers        = flag.Int("workers", 1, "commands per proposal")
	rate           = flag.Int("rate", 0, "commands per second; 0 is unthrottled")
	runTime        = flag.Duration("time", 5*time.Second, "how long to run")
	output         = flag.String("output", "", "write a benchkit result file here")
	verbose        = flag.Bool("verbose", false, "log at debug level")
	cpuprofile     = flag.String("cpuprofile", "", "write a CPU profile here")
	faultKillAfter = flag.Duration("fault-kill-after", 0, "stop replica 1 after this long; -local only")
	viewDuration   = flag.Duration("view-duration", 0, "base round timeout; 0 picks a default")

	// Accepted for the benchkit contract; not acted on yet.
	_ = flag.String("stats-mode", "", "unused")
	_ = flag.Duration("interval", time.Second, "unused")
	_ = flag.String("benchmarks", "", "unused")
	_ = flag.Int("rate-step", 0, "unused")
	_ = flag.Duration("call-timeout", 0, "unused")
)

func main() {
	flag.Parse()
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if err := run(); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run() error {
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}

	switch {
	case *genKeys:
		return writeKeys()
	case *local > 0:
		return runLocal(*local)
	case *self != "":
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
		id := diem.ID(i + 1)
		reps[i] = replica.New(replica.Config{
			ID: id, Key: privs[id], Keys: pubs,
			Transactions: transactions(),
			RoundTimeout: *viewDuration,
			Server:       srvs[i],
		})
	}
	return runAll(reps)
}

// replicaKeys reads id's keys from -keys, or without it derives the seeded
// set every replica computes alike.
func replicaKeys(id diem.ID, n int) (*ecdsa.PrivateKey, map[diem.ID]*ecdsa.PublicKey, error) {
	if *keys != "" {
		return crypto.ReadKeys(*keys, id)
	}
	slog.Warn("no -keys: using insecure seeded keys")
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
	self := strings.TrimSpace(*self)
	idx := slices.Index(addrs, self)
	if idx < 0 {
		return fmt.Errorf("-self %q does not appear in -remotes", self)
	}
	id := diem.ID(idx + 1)
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
		DialOptions:  dialOptions(),
	})})
}

// runAll runs every replica until -time elapses or the process is interrupted,
// then reports what each committed.
func runAll(reps []*replica.Replica) error {
	root, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	start := time.Now()
	root, stop := context.WithTimeout(root, *runTime)
	defer stop()

	var wg sync.WaitGroup
	for i, r := range reps {
		ctx := root
		if *faultKillAfter > 0 && i == 0 {
			var kill context.CancelFunc
			ctx, kill = context.WithTimeout(root, *faultKillAfter)
			defer kill()
		}
		wg.Go(func() {
			if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				slog.Error("replica stopped", "id", r.ID(), "err", err)
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	if err := report(reps); err != nil {
		return err
	}
	if *output == "" {
		return nil
	}
	return writeResults(reps, elapsed)
}

// writeResults writes one benchkit Result per replica to -output, so
// benchkit/cmd/sweep can collect it. An op is a committed block.
func writeResults(reps []*replica.Replica, elapsed time.Duration) error {
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
			Workers: *workers, Payload: *payload, Rate: *rate,
		})
		cfg.SetDuration(runTime.Nanoseconds())
		ops := uint64(len(r.Log()))
		results[i] = benchkit.Result_builder{
			Config:     cfg,
			TotalOps:   ops,
			TotalTime:  elapsed.Nanoseconds(),
			Throughput: float64(ops) / elapsed.Seconds(),
		}.Build()
	}
	label := cmp.Or(*self, "local")
	return benchkit.WriteLabeledReport(results, label, *output)
}

// report prints each replica's committed depth and checks the logs agree over
// their common prefix, which is the whole point of running the thing.
func report(reps []*replica.Replica) error {
	w := os.Stdout
	logs := make([][]*diem.Block, len(reps))
	for i, r := range reps {
		logs[i] = r.Log()
		c := r.Counters()
		fmt.Fprintf(w, "replica %d: committed %d, dropped %d, declined for a missing ancestor %d, rejected %d, queue high-water %d\n",
			r.ID(), len(logs[i]), c.OutboundDropped, r.DeclinedMissingAncestor(), c.Rejected, r.QueueHighWater())
	}
	for i := range logs {
		for j := i + 1; j < len(logs); j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if logs[i][k].ID() != logs[j][k].ID() {
					return fmt.Errorf("replicas %d and %d disagree at commit %d", reps[i].ID(), reps[j].ID(), k)
				}
			}
		}
	}
	if len(reps) > 1 {
		fmt.Fprintln(w, "logs agree over their common prefix")
	}
	return nil
}

// addresses is -remotes as a list, whitespace trimmed. A replica's position in
// it is its ID, so an empty or repeated entry would hand two replicas the same
// identity rather than fail.
func addresses() ([]string, error) {
	if strings.TrimSpace(*remotes) == "" {
		return nil, nil
	}
	addrs := strings.Split(*remotes, ",")
	seen := make(map[string]bool, len(addrs))
	for i, addr := range addrs {
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
	if *payload <= 0 {
		return nil
	}
	return replica.NewPayload(*payload, *workers, *rate).Transactions
}

// GORUMS: NewLocalServers and any real dial need explicit transport
// credentials; there is no insecure default.
func dialOptions() []gorums.DialOption {
	return []gorums.DialOption{gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))}
}

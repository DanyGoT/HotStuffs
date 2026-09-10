// Command hotstuff runs one Chained HotStuff replica, or a whole cluster in a
// single process with -local.
//
// The flag names follow benchkit.StandardFlags so that benchkit/cmd/sweep can
// drive this binary across a cluster later. Adopting the contract costs
// nothing; adopting the dependency is deliberately deferred. Flags the
// prototype does not act on yet are accepted and ignored rather than dropped,
// so the contract stays whole.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/metrics"
	"github.com/DanyGoT/HotStuffs/replica"
	"github.com/relab/gorums"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// Acted on.
	local          = flag.Int("local", 0, "run this many replicas in one process")
	self           = flag.String("self", "", "this replica's address, which must appear in -remotes")
	remotes        = flag.String("remotes", "", "comma-separated addresses of every replica, in ID order 1..n")
	keys           = flag.String("keys", "", "directory holding <id>.key and <id>.pub")
	genKeys        = flag.Bool("gen-keys", false, "write a key pair per replica into -keys and exit")
	payload        = flag.Int("payload", 0, "bytes per command; 0 proposes empty blocks")
	workers        = flag.Int("workers", 1, "commands per proposal")
	rate           = flag.Int("rate", 0, "commands per second; 0 is unthrottled")
	runTime        = flag.Duration("time", 5*time.Second, "how long to run")
	output         = flag.String("output", "", "write the summary here instead of stdout")
	verbose        = flag.Bool("verbose", false, "log at debug level")
	cpuprofile     = flag.String("cpuprofile", "", "write a CPU profile here")
	faultKillAfter = flag.Duration("fault-kill-after", 0, "stop replica 1 after this long; -local only")
	viewDuration   = flag.Duration("view-duration", 0, "base view timeout; 0 picks a default")

	statsMode = flag.String("stats-mode", "", `"ndjson" samples metrics every -interval`)
	interval  = flag.Duration("interval", time.Second, "how often to sample metrics")

	// Accepted for the benchkit contract; not acted on yet.
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
	meters := make([]*metrics.Metrics, n)
	for i := range n {
		id := hotstuff.ID(i + 1)
		meters[i] = metrics.New(hotstuff.SystemClock{}, 0)
		reps[i] = replica.New(replica.Config{
			ID: id, Key: privs[id], Keys: pubs,
			Commands:     commands(),
			ViewDuration: *viewDuration,
			Server:       srvs[i],
			Metrics:      meters[i],
		})
	}
	return runAll(reps, meters)
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
	if *keys == "" {
		return errors.New("-self needs -keys")
	}
	id := hotstuff.ID(idx + 1)
	priv, pubs, err := crypto.ReadKeys(*keys, id)
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, addr := range addrs {
		peers[uint32(i+1)] = addr
	}
	m := metrics.New(hotstuff.SystemClock{}, 0)
	return runAll([]*replica.Replica{replica.New(replica.Config{
		ID: id, Peers: peers, Listen: self,
		Key: priv, Keys: pubs,
		Commands:     commands(),
		ViewDuration: *viewDuration,
		DialOptions:  dialOptions(),
		Metrics:      m,
	})}, []*metrics.Metrics{m})
}

// runAll runs every replica until -time elapses or the process is interrupted,
// then reports what each committed.
func runAll(reps []*replica.Replica, meters []*metrics.Metrics) error {
	root, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	root, stop := context.WithTimeout(root, *runTime)
	defer stop()

	var wg sync.WaitGroup
	if *statsMode == "ndjson" {
		w, closeSamples, err := samplesWriter()
		if err != nil {
			return err
		}
		defer closeSamples()
		for i, m := range meters {
			wg.Go(func() {
				if err := m.Sample(root, w, *interval); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					slog.Error("sampling stopped", "id", reps[i].ID(), "err", err)
				}
			})
		}
	}
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
	return report(reps, meters)
}

// samplesWriter is where NDJSON samples go: -output if given, else stderr, so
// that the end-of-run summary keeps stdout to itself.
func samplesWriter() (io.Writer, func(), error) {
	if *output == "" {
		return os.Stderr, func() {}, nil
	}
	f, err := os.Create(*output)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// report prints each replica's committed depth and checks the logs agree over
// their common prefix, which is the whole point of running the thing.
func report(reps []*replica.Replica, meters []*metrics.Metrics) error {
	w := os.Stdout
	logs := make([][]*hotstuff.Block, len(reps))
	for i, r := range reps {
		logs[i] = r.Log()
		c := r.Counters()
		fmt.Fprintf(w, "replica %d: committed %d, dropped %d, fetch failures %d, rejected %d, queue high-water %d\n",
			r.ID(), len(logs[i]), c.OutboundDropped, c.FetchFailed, c.Rejected, r.QueueHighWater())
		if s := meters[i].Snapshot(); s.LatencySamples > 0 {
			fmt.Fprintf(w, "  commit latency: mean %v over %d samples, max %v\n",
				time.Duration(s.LatencyTotalNs/s.LatencySamples), s.LatencySamples, time.Duration(s.LatencyMaxNs))
		}
	}
	for i := range logs {
		for j := i + 1; j < len(logs); j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if logs[i][k].Hash() != logs[j][k].Hash() {
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

func commands() hotstuff.CommandQueue {
	if *payload <= 0 {
		return replica.NoCommands{}
	}
	return replica.NewPayload(*payload, *workers, *rate)
}

// GORUMS: NewLocalServers and any real dial need explicit transport
// credentials; there is no insecure default.
func dialOptions() []gorums.DialOption {
	return []gorums.DialOption{gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))}
}

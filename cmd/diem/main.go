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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/diembft/crypto"
	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/DanyGoT/diembft/replica"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// options holds the parsed command line.
type options struct {
	std *benchkit.StandardFlags

	local          int
	keys           string
	insecureSeeded bool
	genKeys        bool
	viewDuration   time.Duration
	sendBuffer     uint
}

// newOptions registers the standard benchkit flags and diem's own on fs.
func newOptions(fs *flag.FlagSet) *options {
	o := &options{std: benchkit.RegisterFlags(fs)}
	fs.IntVar(&o.local, "local", 0, "run this many replicas in one process")
	fs.StringVar(&o.keys, "keys", "", "directory holding <id>.key and <id>.pub; required unless -insecure-seeded-keys")
	fs.BoolVar(&o.insecureSeeded, "insecure-seeded-keys", false, "without -keys, derive every replica's keys from a public seed; anyone can sign for any replica")
	fs.BoolVar(&o.genKeys, "gen-keys", false, "write a key pair per replica into -keys and exit")
	fs.DurationVar(&o.viewDuration, "view-duration", 0, "base round timeout; 0 picks a default")
	fs.UintVar(&o.sendBuffer, "send-buffer", 0, "Gorums send queue capacity per peer; 0 picks Gorums' default")
	return o
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(args []string) (err error) {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	o := newOptions(fs)
	_ = fs.Parse(args) // ExitOnError exits on a bad flag
	level := slog.LevelInfo
	if o.std.Verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	stop, err := benchkit.StartProfilers(o.std.CPUProfile, o.std.MemProfile, o.std.Trace)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, stop()) }()

	switch {
	case o.genKeys:
		return o.writeKeys()
	case o.local > 0:
		return o.runLocal(o.local)
	case o.std.Self != "":
		return o.runOne()
	}
	return errors.New("nothing to do: pass -local N, or -self with -remotes")
}

func (o *options) writeKeys() error {
	n := o.local
	if n == 0 {
		addrs, err := o.addresses()
		if err != nil {
			return err
		}
		n = len(addrs)
	}
	if n == 0 || o.keys == "" {
		return errors.New("-gen-keys needs -keys and either -local N or -remotes")
	}
	privs, _, err := crypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	if err := crypto.WriteKeys(o.keys, privs); err != nil {
		return err
	}
	slog.Info("wrote keys", "dir", o.keys, "replicas", n)
	return nil
}

// runLocal runs a whole cluster in one process. gorums.NewLocalServers
// pre-allocates the loopback listeners and numbers the servers 1..n, which is
// what makes this possible at all: WithPeers needs every address before any
// server exists. The replicas share one verifier, which needs only the public
// keys, and so one reject counter.
func (o *options) runLocal(n int) error {
	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	rejected := new(atomic.Uint64)
	verify := diemnet.VerifyInterceptor(diem.NewVerifier(crypto.New(nil, pubs), diem.QuorumSize(n)), rejected)
	srvs, stop, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(o.dialOptions()...),
		gorums.WithLocalServerOptions(gorums.WithServerInterceptors(verify)))
	if err != nil {
		return err
	}
	defer stop()

	reps := make([]*replica.Replica, n)
	for i := range n {
		id := uint32(i + 1)
		reps[i] = replica.New(replica.Config{
			ID: id, Key: privs[id], Keys: pubs,
			Transactions: o.transactions(),
			RoundTimeout: o.viewDuration,
			Measure:      o.std.Options(),
			Server:       srvs[i],
			Rejected:     rejected,
		})
	}
	return o.runAll(reps)
}

// replicaKeys reads id's keys from -keys. Without it, the seeded set every
// replica computes alike is used only when -insecure-seeded-keys asks for it.
func (o *options) replicaKeys(id uint32, n int) (*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	if o.keys != "" {
		return crypto.ReadKeys(o.keys, id)
	}
	if !o.insecureSeeded {
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
func (o *options) runOne() error {
	addrs, err := o.addresses()
	if err != nil {
		return err
	}
	self := strings.TrimSpace(o.std.Self)
	idx := slices.Index(addrs, self)
	if idx < 0 {
		return fmt.Errorf("-self %q does not appear in -remotes", self)
	}
	id := uint32(idx + 1)
	priv, pubs, err := o.replicaKeys(id, len(addrs))
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, addr := range addrs {
		peers[uint32(i+1)] = addr
	}
	return o.runAll([]*replica.Replica{replica.New(replica.Config{
		ID: id, Peers: peers, Listen: self,
		Key: priv, Keys: pubs,
		Transactions: o.transactions(),
		RoundTimeout: o.viewDuration,
		Measure:      o.std.Options(),
		DialOptions:  o.dialOptions(),
	})})
}

// runAll runs every replica for -time from its first round, or until the
// process is interrupted, then reports what each committed.
func (o *options) runAll(reps []*replica.Replica) error {
	root, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	first := root
	if o.std.FaultKillAfter > 0 {
		var kill context.CancelFunc
		first, kill = context.WithTimeout(root, o.std.FaultKillAfter)
		defer kill()
	}

	var wg sync.WaitGroup
	for i, r := range reps {
		ctx := root
		if i == 0 {
			ctx = first
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
	if o.std.Output == "" {
		return nil
	}
	return o.writeResults(reps)
}

// writeResults writes each replica's benchkit Result to -output, so
// benchkit/cmd/sweep can collect it.
func (o *options) writeResults(reps []*replica.Replica) error {
	n := o.local
	if n == 0 {
		addrs, err := o.addresses()
		if err != nil {
			return err
		}
		n = len(addrs)
	}
	results := make([]*benchkit.Result, len(reps))
	for i, r := range reps {
		res := r.Result()
		cfg := res.GetConfig()
		cfg.ApplyDimensions(benchkit.Dimensions{
			Benchmark: "diem", Nodes: n,
			Workers: o.std.Workers, Payload: o.std.Payload, Rate: o.std.Rate,
			SendBuffer: int(o.sendBuffer),
		})
		cfg.SetDuration(int64(o.std.Duration))
		cfg.SetInterval(int64(o.std.Interval))
		cfg.SetStatsMode(o.std.StatsMode)
		results[i] = res
	}
	label := cmp.Or(o.std.Self, "local")
	return benchkit.WriteLabeledReport(results, label, o.std.Output)
}

// report prints each replica's committed depth and checks the logs agree over
// their common prefix, which is the whole point of running the thing.
func report(reps []*replica.Replica) error {
	logs := make([][]*diempb.Block, len(reps))
	for i, r := range reps {
		logs[i] = r.Log()
		c := r.Counters()
		fmt.Printf("replica %d: committed %d (%d commands), dropped %d, declined for a missing ancestor %d, rejected %d\n",
			r.ID(), len(logs[i]), r.Commands(), c.OutboundDropped, r.DeclinedMissingAncestor(), c.Rejected)
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
		fmt.Println("logs agree over their common prefix")
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
func (o *options) addresses() ([]string, error) {
	if len(o.std.Remotes) == 1 && strings.TrimSpace(o.std.Remotes[0]) == "" {
		return nil, nil
	}
	addrs := make([]string, len(o.std.Remotes))
	seen := make(map[string]bool, len(addrs))
	for i, addr := range o.std.Remotes {
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
func (o *options) transactions() func() [][]byte {
	if o.std.Payload <= 0 {
		return nil
	}
	return replica.NewPayload(o.std.Payload, o.std.Workers, o.std.Rate).Transactions
}

// GORUMS: NewLocalServers and any real dial need explicit transport
// credentials; there is no insecure default.
func (o *options) dialOptions() []gorums.DialOption {
	return []gorums.DialOption{
		gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
		gorums.WithSendBufferSize(o.sendBuffer),
	}
}

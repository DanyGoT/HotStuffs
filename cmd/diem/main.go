// Command diem runs one DiemBFT replica, or a whole cluster in a single process
// with -local.
//
// The standard flags come from benchkit.RegisterFlags and -output writes a
// benchkit result file, so benchkit/cmd/sweep can drive this binary across a
// cluster. Standard flags with no meaning for one protocol, such as -benchmarks,
// are accepted and ignored.
//
// diem has no clients, so -workers, in benchkit the number of concurrent
// callers, is the batch here: the most commands a leader puts in one block,
// each -payload bytes. With -payload 0 blocks are empty and -workers is
// unused. The Workers column of diem's result files is that batch.
//
// -fault-kill-after crashes replica -fault-replica that long after its first
// round, the point -time also counts from, so the wait for peers is not in it.
// Through sweep, pass both in -extra-args, for example
// -extra-args "-insecure-seeded-keys -fault-kill-after=10s -fault-replica=1".
package main

import (
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

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/diemnet"
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
	faultReplica   int
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
	fs.IntVar(&o.faultReplica, "fault-replica", 1, "the replica -fault-kill-after stops, counted from its first round as -time is; every node gets the same sweep -extra-args, so only this one exits")
	return o
}

// faultTarget is the ID of the replica -fault-kill-after stops in an n-replica
// cluster, or 0 when no fault is asked for.
func (o *options) faultTarget(n int) (uint32, error) {
	if o.std.FaultKillAfter <= 0 {
		return 0, nil
	}
	if o.faultReplica < 1 || o.faultReplica > n {
		return 0, fmt.Errorf("-fault-replica %d is not one of the replicas 1..%d", o.faultReplica, n)
	}
	return uint32(o.faultReplica), nil
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
	privs, _, err := diemcrypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	if err := diemcrypto.WriteKeys(o.keys, privs); err != nil {
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
	target, err := o.faultTarget(n)
	if err != nil {
		return err
	}
	privs, pubs, err := diemcrypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	rejected := new(atomic.Uint64)
	verify := diemnet.VerifyInterceptor(diem.NewVerifier(diemcrypto.New(nil, pubs), diem.QuorumSize(n)), rejected)
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
			MemPool:      o.mempool(),
			RoundTimeout: o.viewDuration,
			Measure:      o.std.Options(),
			Server:       srvs[i],
			Rejected:     rejected,
		})
	}
	return o.runAll(n, reps, target)
}

// replicaKeys reads id's keys from -keys. Without it, the seeded set every
// replica computes alike is used only when -insecure-seeded-keys asks for it.
func (o *options) replicaKeys(id uint32, n int) (*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	if o.keys != "" {
		return diemcrypto.ReadKeys(o.keys, id)
	}
	if !o.insecureSeeded {
		return nil, nil, errors.New("no -keys: pass -keys DIR, or -insecure-seeded-keys to use public-seed keys")
	}
	slog.Warn("using insecure seeded keys")
	privs, pubs, err := diemcrypto.SeededKeys(n)
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
	target, err := o.faultTarget(len(addrs))
	if err != nil {
		return err
	}
	priv, pubs, err := o.replicaKeys(id, len(addrs))
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, addr := range addrs {
		peers[uint32(i+1)] = addr
	}
	return o.runAll(len(addrs), []*replica.Replica{replica.New(replica.Config{
		ID: id, Peers: peers, Listen: self,
		Key: priv, Keys: pubs,
		MemPool:      o.mempool(),
		RoundTimeout: o.viewDuration,
		Measure:      o.std.Options(),
		DialOptions:  o.dialOptions(),
	})}, target)
}

// runAll runs reps, this process's share of an n-replica cluster, for -time
// from its first round, or until the process is interrupted, then reports what
// each committed. Replica target, if it is here, stops -fault-kill-after past
// its first round, so neither counts the wait for peers.
func (o *options) runAll(n int, reps []*replica.Replica, target uint32) error {
	root, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	var fault *time.Timer
	for _, r := range reps {
		ctx, stop := context.WithCancel(root)
		if r.ID() == target {
			wg.Go(func() {
				select {
				case <-r.Started():
					fault = o.armFault(stop)
				case <-ctx.Done():
				}
			})
		}
		wg.Go(func() {
			defer stop()
			if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				slog.Error("replica stopped", "id", r.ID(), "err", err)
			}
		})
	}
	wg.Wait()
	if fault != nil {
		fault.Stop()
	}
	sums := make([]summary, len(reps))
	results := make([]*benchkit.Result, len(reps))
	for i, r := range reps {
		sums[i], results[i] = summarize(r), r.Result()
	}
	if err := report(os.Stderr, sums); err != nil {
		return err
	}
	if o.std.Output == "" {
		return nil
	}
	return o.writeResults(n, results)
}

// armFault stops the fault target -fault-kill-after from now. With -local the
// target's run is cancelled and it still reports. On the cluster the process
// exits and writes no result, which sweep reads as a crashed node.
func (o *options) armFault(stop context.CancelFunc) *time.Timer {
	if o.local > 0 {
		return time.AfterFunc(o.std.FaultKillAfter, stop)
	}
	return benchkit.ArmFaultInjection(o.std.FaultKillAfter)
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

// mempool is the leader's payload source; nil proposes empty blocks.
func (o *options) mempool() diem.MemPool {
	if o.std.Payload <= 0 {
		return nil
	}
	return replica.NewPayload(o.std.Payload, o.std.Workers, o.std.Rate)
}

// GORUMS: NewLocalServers and any real dial need explicit transport
// credentials; there is no insecure default.
func (o *options) dialOptions() []gorums.DialOption {
	return []gorums.DialOption{
		gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
		gorums.WithSendBufferSize(o.sendBuffer),
	}
}

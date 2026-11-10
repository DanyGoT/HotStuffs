package replica

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/diemnet"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const testRound = 20 * time.Millisecond

// insecureDial is the loopback dial option every test cluster uses; there is
// no TLS story here, only the transport.
var insecureDial = gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))

// waitFor polls pred until it holds or timeout passes, so no test needs a
// sleep to synchronise on a condition.
func waitFor(timeout time.Duration, pred func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if pred() {
			return true
		}
		if time.Now().After(deadline) {
			return pred()
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// cluster builds n replicas on one process's Gorums local servers, dialing
// with dial on top of insecureDial, and returns them with a func that runs them
// under ctx and blocks until every Run has returned.
func cluster(t *testing.T, n int, round time.Duration, dial ...gorums.DialOption) ([]*Replica, func(context.Context)) {
	t.Helper()

	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	rejected := new(atomic.Uint64)
	verify := diemnet.VerifyInterceptor(diem.NewVerifier(crypto.New(nil, pubs), diem.QuorumSize(n)), rejected)
	srvs, stopSrvs, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(append([]gorums.DialOption{insecureDial}, dial...)...),
		gorums.WithLocalServerOptions(gorums.WithServerInterceptors(verify)))
	if err != nil {
		t.Fatalf("NewLocalServers: %v", err)
	}
	t.Cleanup(stopSrvs)

	reps := make([]*Replica, n)
	for i := range n {
		id := uint32(i + 1)
		reps[i] = New(Config{
			ID:           id,
			Key:          privs[id],
			Keys:         pubs,
			Transactions: NewPayload(32, 4, 0).Transactions,
			RoundTimeout: round,
			Measure:      benchkit.Options{Interval: round},
			Server:       srvs[i],
			Rejected:     rejected,
		})
	}

	run := func(ctx context.Context) {
		var wg sync.WaitGroup
		for _, r := range reps {
			wg.Go(func() {
				if err := r.Run(ctx); !errors.Is(err, context.Canceled) {
					t.Errorf("replica %d: Run returned %v, want context.Canceled", r.ID(), err)
				}
			})
		}
		wg.Wait()
	}
	return reps, run
}

func depths(reps []*Replica) []int {
	d := make([]int, len(reps))
	for i, r := range reps {
		d[i] = len(r.Log())
	}
	return d
}

// TestClusterCommitsIdenticalPrefix runs four replicas over real
// Gorums and checks they commit an agreeing, genesis-rooted chain with nothing
// dropped or rejected on the happy path. Every block id on the receiving side
// was recomputed from the wire form, so an agreeing chain is also the proof
// that the wire round trip is faithful.
func TestClusterCommitsIdenticalPrefix(t *testing.T) {
	const n = 4
	reps, run := cluster(t, n, testRound)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	const wantDepth = 20
	if !waitFor(10*time.Second, func() bool {
		for _, r := range reps {
			if len(r.Log()) < wantDepth {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("depths after timeout: %v, want every replica >= %d", depths(reps), wantDepth)
	}

	logs := make([][]*diempb.Block, n)
	for i, r := range reps {
		logs[i] = r.Log()
	}
	for i := range logs {
		for j := i + 1; j < n; j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if !bytes.Equal(logs[i][k].GetId(), logs[j][k].GetId()) {
					t.Fatalf("replicas %d and %d disagree at commit %d: round %d against round %d",
						i+1, j+1, k, logs[i][k].GetRound(), logs[j][k].GetRound())
				}
			}
		}
	}
	for i, log := range logs {
		if !bytes.Equal(log[0].ParentID(), diem.GenesisBlock().GetId()) {
			t.Errorf("replica %d: the first commit does not extend genesis", i+1)
		}
		for k := 1; k < len(log); k++ {
			if !bytes.Equal(log[k].ParentID(), log[k-1].GetId()) {
				t.Errorf("replica %d: commit %d does not extend commit %d", i+1, k, k-1)
			}
			if log[k].GetRound() <= log[k-1].GetRound() {
				t.Errorf("replica %d: commit rounds not increasing: %d then %d", i+1, log[k-1].GetRound(), log[k].GetRound())
			}
		}
	}

	for _, r := range reps {
		c := r.Counters()
		if c.OutboundDropped != 0 || c.Rejected != 0 {
			// Either would mean the harness misconfigured a replica (a missing
			// peer or a bad key), not a protocol-level fault.
			t.Errorf("replica %d: Counters = %+v, want zero OutboundDropped and Rejected", r.ID(), c)
		}
		// Not an assertion: a replica that misses a proposal declines to vote
		// on its descendants until it has fetched it, and the rate is what the
		// report quotes about that gap.
		t.Logf("replica %d: committed %d, declined for a missing ancestor %d",
			r.ID(), len(r.Log()), r.DeclinedMissingAncestor())
	}

	cancel()
	<-allDone
}

// TestResultCountsOwnBlocks pins that a replica's result counts only the
// committed blocks it proposed, so the replicas' throughputs sum to the system
// rate rather than n times it, and that the interval stream covers every op.
func TestResultCountsOwnBlocks(t *testing.T) {
	reps, run := cluster(t, 4, testRound)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	const wantDepth = 20
	if !waitFor(10*time.Second, func() bool { return slices.Min(depths(reps)) >= wantDepth }) {
		t.Fatalf("depths after timeout: %v, want every replica >= %d", depths(reps), wantDepth)
	}
	cancel()
	<-allDone

	for _, r := range reps {
		var own uint64
		for _, b := range r.Log() {
			if b.GetAuthor() == r.ID() {
				own++
			}
		}
		res := r.Result()
		if got := res.GetTotalOps(); got != own {
			t.Errorf("replica %d: TotalOps = %d, want %d own blocks of %d committed", r.ID(), got, own, len(r.Log()))
		}
		var streamed uint64
		for _, e := range res.GetEvents() {
			streamed += e.GetThroughput().GetOps()
		}
		if streamed != own {
			t.Errorf("replica %d: interval events carry %d ops, want %d", r.ID(), streamed, own)
		}
	}
}

// stallStreams makes every stream stop sending, as it does when the peer stops
// reading, until the stream closes.
var stallStreams = gorums.WithGRPCDialOptions(grpc.WithStreamInterceptor(
	func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		cs, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		return stalled{cs}, nil
	}))

type stalled struct{ grpc.ClientStream }

func (s stalled) SendMsg(any) error {
	<-s.Context().Done()
	return s.Context().Err()
}

// sendsWaiting counts the goroutines waiting for space in a full Gorums send
// queue.
func sendsWaiting() int {
	buf := make([]byte, 1<<20)
	for {
		if n := runtime.Stack(buf, true); n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	waiting := 0
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, " [select") && strings.Contains(g, "(*sendQueue).push") {
			waiting++
		}
	}
	return waiting
}

// TestRunStopsWhileASendWaits stalls every stream behind a one-slot send
// queue, so each replica's core ends up waiting for queue space with mu held.
// Cancelling must still stop every replica.
func TestRunStopsWhileASendWaits(t *testing.T) {
	const n = 4
	_, run := cluster(t, n, testRound, gorums.WithSendBufferSize(1), stallStreams)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	if !waitFor(10*time.Second, func() bool { return sendsWaiting() >= n }) {
		t.Fatalf("%d sends wait for queue space, want %d", sendsWaiting(), n)
	}
	cancel()
	select {
	case <-allDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return while a send waited for queue space")
	}
}

// TestNewRejectsMismatchedPeersAndKeys: the public keys are the replica set, so
// a peer list of a different size would give this replica a quorum its peers
// do not share.
func TestNewRejectsMismatchedPeersAndKeys(t *testing.T) {
	privs, pubs, err := crypto.GenerateKeys(4)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	cfg := func() Config {
		return Config{ID: 1, Key: privs[1], Keys: pubs, Listen: "127.0.0.1:0"}
	}

	t.Run("too few peers", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("New accepted 3 peer addresses against 4 public keys")
			}
		}()
		c := cfg()
		c.Peers = map[uint32]string{1: "a:1", 2: "b:2", 3: "c:3"}
		New(c)
	})

	t.Run("own key missing", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("New accepted a key set with no key for this replica's own ID")
			}
		}()
		c := cfg()
		c.ID = 9
		New(c)
	})
}

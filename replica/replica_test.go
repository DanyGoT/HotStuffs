package replica

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/simnet"
	"github.com/relab/gorums"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// insecureDial is the loopback dial option every test cluster uses; there is
// no TLS story here, only the transport.
var insecureDial = gorums.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))

// replicaRun is what a test needs to control and observe one replica's Run
// goroutine independently of the rest of the cluster: cancel stops it alone,
// done closes once Run has returned, and err is valid only once done is
// closed.
type replicaRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// cluster builds n replicas on one process's Gorums local servers, each with
// its own command source, and returns them, one replicaRun per replica for
// controlling it independently, and a func that runs them all under ctx and
// blocks until every Run has returned.
//
// Each replica gets its own context, created here rather than inside run, so
// that a test can read runs[i].cancel before run is ever called without a
// data race. run's only job is to forward ctx's cancellation to every
// replica's own context, which is what lets a single replica be stopped
// without touching the rest.
func cluster(t *testing.T, n int, view time.Duration) ([]*Replica, []*replicaRun, func(context.Context)) {
	t.Helper()

	srvs, stopSrvs, err := gorums.NewLocalServers(n, gorums.WithLocalDialOptions(insecureDial))
	if err != nil {
		t.Fatalf("NewLocalServers: %v", err)
	}
	t.Cleanup(stopSrvs)

	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	reps := make([]*Replica, n)
	runs := make([]*replicaRun, n)
	ctxs := make([]context.Context, n)
	for i := range n {
		id := hotstuff.ID(i + 1)
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i] = ctx
		runs[i] = &replicaRun{cancel: cancel, done: make(chan struct{})}
		reps[i] = New(Config{
			ID:           id,
			Key:          privs[id],
			Keys:         pubs,
			Commands:     NewPayload(32, 4, 0),
			ViewDuration: view,
			Server:       srvs[i],
		})
	}

	run := func(parent context.Context) {
		var wg sync.WaitGroup
		for i, r := range reps {
			wg.Go(func() {
				runs[i].err = r.Run(ctxs[i])
				close(runs[i].done)
			})
			go func() {
				<-parent.Done()
				runs[i].cancel()
			}()
		}
		wg.Wait()
	}

	return reps, runs, run
}

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

// logsOf snapshots every replica's commit log, keyed by ID.
func logsOf(reps []*Replica) map[hotstuff.ID][]*hotstuff.Block {
	logs := make(map[hotstuff.ID][]*hotstuff.Block, len(reps))
	for _, r := range reps {
		logs[r.ID()] = r.Log()
	}
	return logs
}

// minDepth is the shortest log among reps.
func minDepth(reps []*Replica) int {
	lowest := -1
	for _, r := range reps {
		if n := len(r.Log()); lowest == -1 || n < lowest {
			lowest = n
		}
	}
	return lowest
}

// assertExecutesFromGenesis checks that every log is non-empty, that no
// committed block carries the genesis view, and that the first commit
// extends genesis directly.
func assertExecutesFromGenesis(t *testing.T, logs map[hotstuff.ID][]*hotstuff.Block) {
	t.Helper()
	for id, log := range logs {
		if len(log) == 0 {
			t.Errorf("replica %d: empty commit log", id)
			continue
		}
		for _, b := range log {
			if b.View() == 0 {
				t.Errorf("replica %d: committed a block at genesis view", id)
			}
		}
		if log[0].Parent() != hotstuff.GenesisHash() {
			t.Errorf("replica %d: log[0] parent is not genesis", id)
		}
	}
}

// assertCommonPrefixAgrees checks entry-for-entry agreement over the shortest
// log, independently of simnet.CheckSafety, so that check does not rest
// solely on the oracle.
func assertCommonPrefixAgrees(t *testing.T, logs map[hotstuff.ID][]*hotstuff.Block) {
	t.Helper()
	ids := make([]hotstuff.ID, 0, len(logs))
	for id := range logs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return
	}
	n := len(logs[ids[0]])
	for _, id := range ids[1:] {
		if l := len(logs[id]); l < n {
			n = l
		}
	}
	ref := logs[ids[0]]
	for k := range n {
		for _, id := range ids[1:] {
			if logs[id][k].Hash() != ref[k].Hash() {
				t.Errorf("index %d: replica %d committed view %d, replica %d committed view %d",
					k, id, logs[id][k].View(), ids[0], ref[k].View())
			}
		}
	}
}

// waitForErr blocks until run's error is available or fails the test.
func waitForErr(t *testing.T, rr *replicaRun, timeout time.Duration) error {
	t.Helper()
	select {
	case <-rr.done:
		return rr.err
	case <-time.After(timeout):
		t.Fatal("replica did not stop in time")
		return nil
	}
}

const testView = 20 * time.Millisecond

// TestClusterCommitsIdenticalPrefix runs four replicas and checks that they
// commit an agreeing, genesis-rooted history with nothing dropped or
// rejected on the happy path.
func TestClusterCommitsIdenticalPrefix(t *testing.T) {
	const n = 4
	reps, runs, run := cluster(t, n, testView)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	const wantDepth = 20
	if !waitFor(5*time.Second, func() bool { return minDepth(reps) >= wantDepth }) {
		t.Fatalf("depths after timeout: %v, want every replica >= %d", depths(reps), wantDepth)
	}

	logs := logsOf(reps)
	simnet.CheckSafety(t, logs)
	assertCommonPrefixAgrees(t, logs)
	assertExecutesFromGenesis(t, logs)

	for _, r := range reps {
		c := r.Counters()
		if c.OutboundDropped != 0 || c.Rejected != 0 {
			// Either would mean the harness misconfigured a replica (e.g. a
			// missing peer or a bad key), not a protocol-level fault.
			t.Errorf("replica %d: Counters = %+v, want zero OutboundDropped and Rejected", r.ID(), c)
		}
	}

	cancel()
	<-allDone
	for i, rr := range runs {
		if !errors.Is(rr.err, context.Canceled) {
			t.Errorf("replica %d: Run returned %v, want context.Canceled", i+1, rr.err)
		}
	}
}

// TestLeaderCrashSurvivorsProgress stops the view-1 leader (ID 2, index 1 of
// 4) mid-run and checks that the three survivors keep committing while the
// crashed replica's log stays frozen and remains a safe prefix of theirs.
//
// Survivors keep going because a crashed replica now costs only the views it
// leads: votes and timeouts are broadcast to everyone, not unicast to the
// next leader, so the others still reach a quorum without it.
func TestLeaderCrashSurvivorsProgress(t *testing.T) {
	const n, leaderIdx = 4, 1
	reps, runs, run := cluster(t, n, testView)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	if !waitFor(5*time.Second, func() bool { return minDepth(reps) >= 5 }) {
		t.Fatalf("depths after timeout: %v, want every replica >= 5 before crashing the leader", depths(reps))
	}

	simnet.CheckSafety(t, logsOf(reps)) // safe before the crash
	baseline := depths(reps)

	runs[leaderIdx].cancel()
	if err := waitForErr(t, runs[leaderIdx], 5*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("crashed replica %d: Run returned %v, want context.Canceled", reps[leaderIdx].ID(), err)
	}
	crashedDepth := len(reps[leaderIdx].Log())

	const wantGrowth = 10
	if !waitFor(10*time.Second, func() bool {
		for i, r := range reps {
			if i == leaderIdx {
				continue
			}
			if len(r.Log()) < baseline[i]+wantGrowth {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("depths after timeout: %v, baseline %v, want every survivor >= baseline+%d", depths(reps), baseline, wantGrowth)
	}

	logs := logsOf(reps) // all four, the crashed one included
	simnet.CheckSafety(t, logs)
	assertCommonPrefixAgrees(t, logs)
	assertExecutesFromGenesis(t, logs)

	if got := len(reps[leaderIdx].Log()); got != crashedDepth {
		t.Errorf("crashed replica %d: log grew from %d to %d after it stopped", reps[leaderIdx].ID(), crashedDepth, got)
	}

	cancel()
	<-allDone
}

// depths is each replica's current commit-log length, in replica order.
func depths(reps []*Replica) []int {
	d := make([]int, len(reps))
	for i, r := range reps {
		d[i] = len(r.Log())
	}
	return d
}

// TestClusterViaPeerAddresses wires four replicas through Config.Peers and
// Config.Listen instead of Config.Server. Every address has to be known
// before any replica is constructed, because WithPeers takes them all up
// front — which is exactly why Config.Server exists for the single-process
// case: gorums.NewLocalServers can allocate the listeners first and hand them
// in afterwards.
//
// GORUMS: this takes about a second longer than the Config.Server clusters,
// because a peer that was not listening at dial time is only retried on a
// fixed backoff. There is no "connect when it appears" path short of
// pre-binding.
func TestClusterViaPeerAddresses(t *testing.T) {
	const n = 4
	addrs := make(map[uint32]string, n)
	for i := 1; i <= n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		addrs[uint32(i)] = l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatalf("close probe listener: %v", err)
		}
	}
	// A closed port can in principle be reused by something else before the
	// replica's own server rebinds it; if this test is ever flaky, that race
	// is the reason, and Config.Server (see cluster above) is the fix, not a
	// workaround here.

	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	reps := make([]*Replica, n)
	runs := make([]*replicaRun, n)
	ctxs := make([]context.Context, n)
	for i := range n {
		id := hotstuff.ID(i + 1)
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i] = ctx
		runs[i] = &replicaRun{cancel: cancel, done: make(chan struct{})}
		reps[i] = New(Config{
			ID:           id,
			Peers:        addrs,
			Listen:       addrs[uint32(id)],
			Key:          privs[id],
			Keys:         pubs,
			Commands:     NewPayload(32, 4, 0),
			ViewDuration: testView,
			DialOptions:  []gorums.DialOption{insecureDial},
		})
	}

	parent, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var wg sync.WaitGroup
	for i, r := range reps {
		wg.Go(func() {
			runs[i].err = r.Run(ctxs[i])
			close(runs[i].done)
		})
		go func() {
			<-parent.Done()
			runs[i].cancel()
		}()
	}

	if !waitFor(5*time.Second, func() bool { return minDepth(reps) >= 5 }) {
		t.Fatalf("depths after timeout: %v, want every replica >= 5", depths(reps))
	}
	simnet.CheckSafety(t, logsOf(reps))

	cancel()
	wg.Wait()
}

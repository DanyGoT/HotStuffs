package replica

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/relab/gorums"
)

// diemCluster builds n DiemBFT replicas on one process's Gorums local servers
// and returns them with a func that runs them under ctx and blocks until every
// Run has returned.
func diemCluster(t *testing.T, n int, round time.Duration) ([]*Diem, func(context.Context)) {
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

	reps := make([]*Diem, n)
	for i := range n {
		id := hotstuff.ID(i + 1)
		reps[i] = NewDiem(Config{
			ID:           id,
			Key:          privs[id],
			Keys:         pubs,
			Commands:     NewPayload(32, 4, 0),
			ViewDuration: round,
			Server:       srvs[i],
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

func diemDepths(reps []*Diem) []int {
	d := make([]int, len(reps))
	for i, r := range reps {
		d[i] = len(r.Log())
	}
	return d
}

// TestDiemClusterCommitsIdenticalPrefix runs four DiemBFT replicas over real
// Gorums and checks they commit an agreeing, genesis-rooted chain with nothing
// dropped or rejected on the happy path. Every block id on the receiving side
// was recomputed from the wire form, so an agreeing chain is also the proof
// that the wire round trip is faithful.
func TestDiemClusterCommitsIdenticalPrefix(t *testing.T) {
	const n = 4
	reps, run := diemCluster(t, n, testView)

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
		t.Fatalf("depths after timeout: %v, want every replica >= %d", diemDepths(reps), wantDepth)
	}

	logs := make([][]*diem.Block, n)
	for i, r := range reps {
		logs[i] = r.Log()
	}
	for i := range logs {
		for j := i + 1; j < n; j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if logs[i][k].ID() != logs[j][k].ID() {
					t.Fatalf("replicas %d and %d disagree at commit %d: round %d against round %d",
						i+1, j+1, k, logs[i][k].Round, logs[j][k].Round)
				}
			}
		}
	}
	for i, log := range logs {
		if log[0].ParentID() != diem.GenesisBlock().ID() {
			t.Errorf("replica %d: the first commit does not extend genesis", i+1)
		}
		for k := 1; k < len(log); k++ {
			if log[k].ParentID() != log[k-1].ID() {
				t.Errorf("replica %d: commit %d does not extend commit %d", i+1, k, k-1)
			}
			if log[k].Round <= log[k-1].Round {
				t.Errorf("replica %d: commit rounds not increasing: %d then %d", i+1, log[k-1].Round, log[k].Round)
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
		// Not an assertion: with no block-sync, a replica that misses a
		// proposal declines to vote on its descendants, and the rate is what
		// the report quotes about that gap.
		t.Logf("replica %d: committed %d, declined for a missing ancestor %d, queue high-water %d",
			r.ID(), len(r.Log()), r.DeclinedMissingAncestor(), r.QueueHighWater())
	}

	cancel()
	<-allDone
}

// TestNewDiemRejectsMismatchedPeersAndKeys pins the same cross-check Replica
// makes: the public keys are the replica set, so a peer list of a different
// size would give this replica a quorum its peers do not share.
func TestNewDiemRejectsMismatchedPeersAndKeys(t *testing.T) {
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
				t.Error("NewDiem accepted 3 peer addresses against 4 public keys")
			}
		}()
		c := cfg()
		c.Peers = map[uint32]string{1: "a:1", 2: "b:2", 3: "c:3"}
		NewDiem(c)
	})

	t.Run("own key missing", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("NewDiem accepted a key set with no key for this replica's own ID")
			}
		}()
		c := cfg()
		c.ID = 9
		NewDiem(c)
	})
}

package simnet

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// minLog is the shallowest commit log among the live (non-crashed) replicas.
// RunUntil's predicate is checked before each delivery, so it can fire while
// some live replica still lags a delivery or two behind whichever one a
// predicate over Log(0) alone would name.
func minLog(nt *Net) int {
	lowest := -1
	for i := range nt.N() {
		if nt.replicas[i].crashed {
			continue
		}
		if l := len(nt.Log(i)); lowest == -1 || l < lowest {
			lowest = l
		}
	}
	return max(lowest, 0)
}

// minLogOf is minLog restricted to the given indices, for scenarios (a
// partition) where "live" is narrower than "not crashed".
func minLogOf(nt *Net, idxs ...int) int {
	lowest := -1
	for _, i := range idxs {
		if l := len(nt.Log(i)); lowest == -1 || l < lowest {
			lowest = l
		}
	}
	return max(lowest, 0)
}

// hashesOf reduces a commit log to its hashes, so two logs from different
// Nets can be compared with slices.Equal instead of comparing *Block pointers.
func hashesOf(log []*hotstuff.Block) []hotstuff.Hash {
	out := make([]hotstuff.Hash, len(log))
	for i, b := range log {
		out[i] = b.Hash()
	}
	return out
}

// prefixEqual reports whether a and b agree over their common prefix.
func prefixEqual(a, b []*hotstuff.Block) bool {
	for i := range min(len(a), len(b)) {
		if a[i].Hash() != b[i].Hash() {
			return false
		}
	}
	return true
}

func TestHappyPathCommitsAndAgree(t *testing.T) {
	nt := New(t, 4, WithSeed(1), WithViewDuration(10*time.Millisecond))
	if !nt.RunUntil(func() bool { return minLog(nt) >= 5 }, 20000) {
		t.Fatalf("RunUntil never reached depth 5, minLog=%d", minLog(nt))
	}
	for i := range nt.N() {
		if l := len(nt.Log(i)); l < 5 {
			t.Errorf("replica %d log has %d entries, want >= 5", i, l)
		}
	}
	for i := 1; i < nt.N(); i++ {
		if !prefixEqual(nt.Log(0), nt.Log(i)) {
			t.Errorf("replica %d log disagrees with replica 0 over their common prefix", i)
		}
	}
	nt.CheckSafety(t)

	trace := nt.Trace()
	if len(trace) == 0 {
		t.Fatal("Trace() is empty")
	}
	if !strings.Contains(trace[0], "propose view=1") {
		t.Errorf("first trace line = %q, want it to mention propose view=1", trace[0])
	}
}

func TestCommitsStartAtView1(t *testing.T) {
	nt := New(t, 4, WithSeed(2), WithViewDuration(10*time.Millisecond))
	if !nt.RunUntil(func() bool { return minLog(nt) >= 5 }, 20000) {
		t.Fatalf("RunUntil never reached depth 5, minLog=%d", minLog(nt))
	}
	for i := range nt.N() {
		for k, b := range nt.Log(i) {
			if b.View() == 0 {
				t.Errorf("replica %d log[%d] has view 0 (genesis was executed)", i, k)
			}
		}
	}
	if v := nt.Log(0)[0].View(); v != 1 {
		t.Errorf("Log(0)[0].View() = %d, want 1", v)
	}
}

func TestDeliverReportsCount(t *testing.T) {
	nt := New(t, 4)
	if got := nt.Deliver(0); got != 0 {
		t.Errorf("Deliver(0) = %d, want 0", got)
	}
	if got := nt.Deliver(1); got != 1 {
		t.Errorf("Deliver(1) = %d, want 1 (schedule is non-empty right after New)", got)
	}

	// A healthy, fully connected net never runs dry on its own: every view's
	// quorum re-arms the next one, forever. Crash all but one replica so
	// nothing can reach quorum again and the remaining handful of scheduled
	// items is all there will ever be.
	nt.Crash(1)
	nt.Crash(2)
	nt.Crash(3)
	if got := nt.Deliver(1000); got >= 1000 {
		t.Errorf("Deliver(1000) = %d, want less than 1000 once the schedule runs dry", got)
	}
	if got := nt.Deliver(1); got != 0 {
		t.Errorf("Deliver(1) on a drained schedule = %d, want 0", got)
	}
}

func TestSameSeedReplaysIdentically(t *testing.T) {
	build := func() *Net {
		nt := New(t, 4, WithSeed(7), WithViewDuration(10*time.Millisecond))
		nt.RunUntil(func() bool { return minLog(nt) >= 4 }, 20000)
		return nt
	}
	a, b := build(), build()

	if !slices.Equal(a.Trace(), b.Trace()) {
		t.Fatalf("traces differ for the same seed:\na=%v\nb=%v", a.Trace(), b.Trace())
	}
	for i := range a.N() {
		if !slices.Equal(hashesOf(a.Log(i)), hashesOf(b.Log(i))) {
			t.Errorf("replica %d logs differ for the same seed", i)
		}
	}
}

func TestDifferentSeedsExploreDifferentOrders(t *testing.T) {
	build := func(seed int64) []string {
		nt := New(t, 4, WithSeed(seed), WithViewDuration(10*time.Millisecond))
		nt.RunUntil(func() bool { return minLog(nt) >= 4 }, 20000)
		return nt.Trace()
	}
	base := build(1)
	for seed := int64(2); seed <= 6; seed++ {
		if !slices.Equal(base, build(seed)) {
			return // at least one seed diverged: the seed does something
		}
	}
	t.Fatal("seeds 1..6 all produced identical traces")
}

func TestLeaderCrashProgressResumes(t *testing.T) {
	nt := New(t, 4, WithSeed(1), WithViewDuration(10*time.Millisecond))
	nt.Crash(1) // index 1 = ID 2 = leader of view 1
	live := []int{0, 2, 3}
	if !nt.RunUntil(func() bool { return minLogOf(nt, live...) >= 3 }, 20000) {
		t.Fatalf("progress stalled after leader crash, minLog=%d", minLogOf(nt, live...))
	}
	nt.CheckSafety(t)

	stalled := len(nt.Log(1))
	nt.RunUntil(func() bool { return false }, 2000)
	if got := len(nt.Log(1)); got != stalled {
		t.Errorf("crashed replica's log grew from %d to %d", stalled, got)
	}
}

// TestCrashMatrix is the regression test for multicast votes: votes are
// broadcast to every replica, not unicast to the next leader, so a crashed
// replica costs only the view it leads. With unicast-to-next-leader the n=4
// and n=7/[1,5] rows below never commit at all, which is why this table
// exists.
func TestCrashMatrix(t *testing.T) {
	cases := []struct {
		n     int
		crash []int
	}{
		{4, []int{1}},
		{7, []int{1}},
		{7, []int{1, 3}},
		{7, []int{1, 5}},
		{10, []int{1}},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("n=%d/crash=%v", c.n, c.crash), func(t *testing.T) {
			nt := New(t, c.n, WithSeed(1), WithViewDuration(10*time.Millisecond))
			for _, idx := range c.crash {
				nt.Crash(idx)
			}
			var live []int
			for i := range c.n {
				if !slices.Contains(c.crash, i) {
					live = append(live, i)
				}
			}
			if !nt.RunUntil(func() bool { return minLogOf(nt, live...) >= 3 }, 50000) {
				t.Fatalf("progress stalled, minLog=%d", minLogOf(nt, live...))
			}
			nt.CheckSafety(t)
		})
	}
}

func TestMaxFaultToleranceThenStall(t *testing.T) {
	const n = 7
	f := hotstuff.Faulty(n)
	if f != 2 {
		t.Fatalf("hotstuff.Faulty(7) = %d, want 2", f)
	}

	nt := New(t, n, WithSeed(1), WithViewDuration(10*time.Millisecond))
	nt.Crash(1)
	nt.Crash(3)
	tolerant := []int{0, 2, 4, 5, 6}
	if !nt.RunUntil(func() bool { return minLogOf(nt, tolerant...) >= 3 }, 50000) {
		t.Fatalf("progress stalled at the tolerated fault count, minLog=%d", minLogOf(nt, tolerant...))
	}
	nt.CheckSafety(t)

	// A third crash exceeds Faulty(7): 4 live replicas cannot form the quorum
	// of 5, so the commit depth must stop growing.
	nt.Crash(5)
	stillLive := []int{0, 2, 4, 6}
	before := minLogOf(nt, stillLive...)
	nt.RunUntil(func() bool { return false }, 20000)
	if got := minLogOf(nt, stillLive...); got != before {
		t.Errorf("commit depth grew from %d to %d past the tolerated fault count", before, got)
	}
}

func TestPartitionNoQuorumThenHeal(t *testing.T) {
	nt := New(t, 4, WithSeed(1), WithViewDuration(10*time.Millisecond))
	nt.Partition([]int{0, 1}, []int{2, 3}) // neither side has a quorum of 3
	before := minLog(nt)
	nt.RunUntil(func() bool { return false }, 5000)
	if got := minLog(nt); got != before {
		t.Errorf("commit depth grew from %d to %d while partitioned without a quorum", before, got)
	}
	nt.CheckSafety(t)

	nt.Heal()
	if !nt.RunUntil(func() bool { return minLog(nt) >= before+2 }, 20000) {
		t.Fatalf("progress did not resume after Heal, minLog=%d", minLog(nt))
	}
	nt.CheckSafety(t)
}

func TestPartitionWithQuorumKeepsGoing(t *testing.T) {
	nt := New(t, 4, WithSeed(1), WithViewDuration(10*time.Millisecond))
	nt.Partition([]int{0, 1, 2}, []int{3})
	majority := []int{0, 1, 2}
	if !nt.RunUntil(func() bool { return minLogOf(nt, majority...) >= 3 }, 20000) {
		t.Fatalf("majority side stalled, minLog=%d", minLogOf(nt, majority...))
	}
	if got := len(nt.Log(3)); got != 0 {
		t.Errorf("isolated replica committed %d entries while partitioned, want 0", got)
	}

	nt.Heal()
	target := minLogOf(nt, majority...)
	if !nt.RunUntil(func() bool { return len(nt.Log(3)) >= target }, 20000) {
		t.Fatalf("isolated replica never caught up, log has %d entries, want >= %d", len(nt.Log(3)), target)
	}
	if !prefixEqual(nt.Log(0), nt.Log(3)) {
		t.Error("backfilled replica disagrees with replica 0 over their common prefix")
	}
	nt.CheckSafety(t)
}

// TestSeededPartitionSweep is the highest value-per-line test in this suite:
// a hundred seeded schedules, each run through a partition and a heal, all
// checked against the safety oracle. A failure names its seed, so it
// reproduces from one number.
func TestSeededPartitionSweep(t *testing.T) {
	progressed := 0
	for seed := int64(1); seed <= 100; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			nt := New(t, 4, WithSeed(seed), WithViewDuration(10*time.Millisecond))
			before := minLog(nt)
			nt.RunUntil(func() bool { return minLog(nt) >= 3 }, 500)

			switch seed % 3 {
			case 0:
				nt.Partition([]int{0, 1}, []int{2, 3}) // no quorum either side
			case 1:
				nt.Partition([]int{0}, []int{1, 2, 3}) // one isolated, one quorum
			case 2:
				nt.Partition([]int{0, 1, 2}, []int{3}) // majority quorum, one isolated
			}
			nt.RunUntil(func() bool { return false }, 300)

			nt.Heal()
			nt.RunUntil(func() bool { return minLog(nt) >= before+3 }, 1500)

			if errs := SafetyErrors(logsOf(nt)); len(errs) != 0 {
				t.Fatalf("seed %d: safety violated: %v", seed, errs)
			}
			if minLog(nt) > before {
				progressed++
			}
		})
	}
	if progressed < 50 {
		t.Errorf("only %d/100 seeds made any progress, want most of them to", progressed)
	}
}

// logsOf snapshots every replica's commit log, keyed by ID, for SafetyErrors.
func logsOf(nt *Net) map[hotstuff.ID][]*hotstuff.Block {
	logs := make(map[hotstuff.ID][]*hotstuff.Block, nt.N())
	for i := range nt.N() {
		logs[nt.ID(i)] = nt.Log(i)
	}
	return logs
}

// --- Fault injection ---

// countLabel counts trace lines carrying the given delivery label.
func countLabel(trace []string, label string) int {
	n := 0
	for _, line := range trace {
		if strings.Contains(line, " "+label+" ") {
			n++
		}
	}
	return n
}

// TestInjectDeliversAndDropsUnverifiable is the fault-injection contract: an
// injected event the receiver accepts is delivered like any other, and one it
// rejects is dropped rather than failing the test, which is what a real
// handler does with a Byzantine message.
func TestInjectDeliversAndDropsUnverifiable(t *testing.T) {
	nt := New(t, 4, WithViewDuration(10*time.Millisecond))

	var bh hotstuff.Hash
	bh[0] = 0x5A
	sig, err := nocrypto.New(3, 4).Sign(hotstuff.VoteDigest(7, bh))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	nt.Inject(2, 0, hotstuff.VoteEvent{PartialCert: hotstuff.PartialCert{View: 7, BlockHash: bh, Sig: sig}})
	// View 0 never verifies, whatever it is signed with.
	nt.Inject(2, 0, hotstuff.VoteEvent{PartialCert: hotstuff.PartialCert{View: 0, BlockHash: bh, Sig: sig}})

	nt.Deliver(len(nt.schedule)) // FIFO without a seed, so both injections land

	if n := countLabel(nt.Trace(), "inject"); n != 1 {
		t.Errorf("trace has %d injected deliveries, want 1: the unverifiable one must be dropped", n)
	}
}

// TestDropPredicateSkipsSelectedDeliveries checks that Drop discards exactly
// what it names and nothing else: replica 1's votes never arrive, yet the
// remaining three still reach a quorum and commit.
func TestDropPredicateSkipsSelectedDeliveries(t *testing.T) {
	nt := New(t, 4, WithSeed(1), WithViewDuration(10*time.Millisecond))
	nt.Drop(func(d Delivery) bool {
		_, isVote := d.Event.(hotstuff.VoteEvent)
		return isVote && d.From == 0
	})

	if !nt.RunUntil(func() bool { return minLog(nt) >= 3 }, 20000) {
		t.Fatalf("progress stalled with one replica's votes dropped, minLog=%d", minLog(nt))
	}
	for _, line := range nt.Trace() {
		if strings.Contains(line, "r1->") && strings.Contains(line, " vote ") {
			t.Fatalf("a dropped delivery was delivered: %q", line)
		}
	}
	nt.CheckSafety(t)
}

// TestDroppedFetchesRecoverOnceAnswered is the end-to-end half of the fetch
// retry: an isolated replica falls behind, every backfill request it makes
// while catching up is dropped, and it still catches up once they are
// answered again — which it can only do by asking a second time.
func TestDroppedFetchesRecoverOnceAnswered(t *testing.T) {
	nt := New(t, 4, WithSeed(1), WithViewDuration(10*time.Millisecond))
	nt.Drop(func(d Delivery) bool { return d.Event == nil }) // every backfill request

	majority := []int{0, 1, 2}
	nt.Partition(majority, []int{3})
	if !nt.RunUntil(func() bool { return minLogOf(nt, majority...) >= 3 }, 20000) {
		t.Fatalf("majority side stalled, minLog=%d", minLogOf(nt, majority...))
	}

	nt.Heal()
	nt.RunUntil(func() bool { return false }, 2000)
	if got := len(nt.Log(3)); got != 0 {
		t.Fatalf("isolated replica committed %d entries with every backfill dropped, want 0", got)
	}

	nt.Drop(nil)
	target := minLogOf(nt, majority...)
	if !nt.RunUntil(func() bool { return len(nt.Log(3)) >= target }, 20000) {
		t.Fatalf("replica never re-requested its gap: log has %d entries, want >= %d", len(nt.Log(3)), target)
	}
	if !prefixEqual(nt.Log(0), nt.Log(3)) {
		t.Error("backfilled replica disagrees with replica 0 over their common prefix")
	}
	nt.CheckSafety(t)
}

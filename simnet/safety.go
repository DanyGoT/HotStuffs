package simnet

import (
	"fmt"
	"slices"
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// CheckSafety reports every safety violation in logs as a test error.
func CheckSafety(t testing.TB, logs map[hotstuff.ID][]*hotstuff.Block) {
	t.Helper()
	for _, err := range SafetyErrors(logs) {
		t.Error(err)
	}
}

// SafetyErrors is the safety oracle. Over commit logs from any number of
// replicas it checks:
//  1. each log is a chain: log[k].Parent() == log[k-1].Hash()
//  2. views strictly increase within a log
//  3. pairwise prefix agreement across replicas
//
// Point 3 is the Twins oracle; 1 and 2 are cheap local invariants that catch
// commit-ordering bugs long before an agreement violation shows up. It returns
// errors rather than failing a test so that the oracle itself is testable.
func SafetyErrors(logs map[hotstuff.ID][]*hotstuff.Block) []error {
	ids := make([]hotstuff.ID, 0, len(logs))
	for id := range logs {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var errs []error
	for _, id := range ids {
		errs = append(errs, chainErrors(id, logs[id])...)
	}
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			errs = append(errs, prefixErrors(a, logs[a], b, logs[b])...)
		}
	}
	return errs
}

// chainErrors checks points 1 and 2 for one replica's log. Every replica
// executes forward from genesis, so the first entry's parent is always genesis
// however far into a run the replica made its first commit.
func chainErrors(id hotstuff.ID, log []*hotstuff.Block) []error {
	var errs []error
	if len(log) > 0 && log[0].Parent() != hotstuff.GenesisHash() {
		errs = append(errs, fmt.Errorf("replica %d: log[0] parent %x is not genesis", id, log[0].Parent()))
	}
	for k := 1; k < len(log); k++ {
		if log[k].Parent() != log[k-1].Hash() {
			errs = append(errs, fmt.Errorf("replica %d: log[%d] parent %x != log[%d] hash %x",
				id, k, log[k].Parent(), k-1, log[k-1].Hash()))
		}
		if log[k].View() <= log[k-1].View() {
			errs = append(errs, fmt.Errorf("replica %d: log[%d] view %d does not exceed log[%d] view %d",
				id, k, log[k].View(), k-1, log[k-1].View()))
		}
	}
	return errs
}

// prefixErrors checks that one log is a prefix of the other. Both grow forward
// from genesis, so index comparison is the real prefix property and is strictly
// stronger than matching commits up by view.
func prefixErrors(aID hotstuff.ID, a []*hotstuff.Block, bID hotstuff.ID, b []*hotstuff.Block) []error {
	for k := range min(len(a), len(b)) {
		if a[k].Hash() != b[k].Hash() {
			return []error{fmt.Errorf("safety violation: replica %d committed view %d at index %d where replica %d committed view %d",
				aID, a[k].View(), k, bID, b[k].View())}
		}
	}
	return nil
}

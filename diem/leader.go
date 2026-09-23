package diem

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
)

// LeaderElection is the paper's LeaderElection module (3.7). It maps rounds to
// leaders by two paths: reputation when the chain is committing cleanly, and
// round-robin otherwise.
//
// Rotating every round gives every honest replica a turn, but keeps electing
// crashed ones with no evidence they recovered. Reputation elects from the
// replicas that demonstrably signed recent commits, which is what bounds the
// damage crash faults do to latency; excluding the authors of the most recent
// commits is what keeps chain quality under a Byzantine adversary.
type LeaderElection struct {
	validators  []ID
	windowSize  int
	excludeSize int

	ledger    *MemLedger
	pacemaker *Pacemaker

	reputationLeaders map[Round]ID
}

// NewLeaderElection returns the leader election for a replica set. validators
// is sorted, so every replica indexes the same rotation. windowSize is how far
// back the active set is read; excludeSize is how many recent commit authors
// are held out of it, and the paper puts it between f and 2f.
func NewLeaderElection(validators []ID, windowSize, excludeSize int, ledger *MemLedger, pacemaker *Pacemaker) *LeaderElection {
	v := slices.Clone(validators)
	slices.Sort(v)
	return &LeaderElection{
		validators:        v,
		windowSize:        windowSize,
		excludeSize:       excludeSize,
		ledger:            ledger,
		pacemaker:         pacemaker,
		reputationLeaders: map[Round]ID{},
	}
}

// GetLeader names the leader of round: the reputation-elected one when this
// replica elected one, and the round-robin fallback otherwise.
//
// The fallback gives each validator two consecutive rounds. That is what makes
// the pipeline's happy path work without a handover: the leader of round r+1
// collects the votes for round r, and half the time it is the same replica.
func (e *LeaderElection) GetLeader(round Round) ID {
	if id, ok := e.reputationLeaders[round]; ok {
		return id
	}
	return e.validators[(uint64(round)/2)%uint64(len(e.validators))]
}

// UpdateLeaders elects the leader of the round after next, but only when qc
// certifies a contiguous 2-chain that this replica is exactly one round past —
// that is, when the commit information is fresh enough that every honest
// replica seeing it agrees. Replicas that do not see it fall back to
// round-robin, so they may briefly disagree; the paper bounds how often after
// GST.
func (e *LeaderElection) UpdateLeaders(qc *QC) {
	if qc == nil {
		return
	}
	extendedRound := qc.VoteInfo.ParentRound
	qcRound := qc.VoteInfo.Round
	currentRound := e.pacemaker.CurrentRound()
	if extendedRound+1 != qcRound || qcRound+1 != currentRound {
		return
	}
	if id, ok := e.electReputationLeader(qc); ok {
		e.reputationLeaders[currentRound+1] = id
	}
	for r := range e.reputationLeaders {
		if r < currentRound {
			delete(e.reputationLeaders, r) // a round already left behind needs no leader
		}
	}
}

// electReputationLeader walks back over committed blocks, collecting the
// replicas that signed the last windowSize of them and the authors of the last
// excludeSize, then picks deterministically from the difference.
//
// The paper's loop has no exit for a history shorter than the window; this one
// stops when the ledger no longer holds the next block back, which happens
// both early in a run and once the retention bound has dropped old blocks.
func (e *LeaderElection) electReputationLeader(qc *QC) (ID, bool) {
	active := map[ID]struct{}{}
	excluded := map[ID]struct{}{}

	current := qc
	for i := 0; i < e.windowSize || len(excluded) < e.excludeSize; i++ {
		block, ok := e.ledger.CommittedBlock(current.VoteInfo.ParentID)
		if !ok {
			break
		}
		if i < e.windowSize {
			for _, s := range current.Signatures {
				active[s.Signer] = struct{}{}
			}
		}
		if len(excluded) < e.excludeSize {
			excluded[block.Author] = struct{}{}
		}
		current = block.QC
		if current == nil {
			break
		}
	}

	candidates := make([]ID, 0, len(active))
	for id := range active {
		if _, out := excluded[id]; !out {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		// The paper argues the difference is non-empty; it can still be empty
		// against a history too short to fill the window. Round-robin then
		// stands, which is the same fallback a replica that saw no commit uses.
		return 0, false
	}
	slices.Sort(candidates)
	return candidates[pick(qc.VoteInfo.Round, len(candidates))], true
}

// pick is the paper's pick_one(seed): a deterministic index into the candidate
// set. Every replica that elects at all must elect the same leader, so this
// must be a function of the seed alone — hashing the round spreads consecutive
// seeds across the set, which taking the round modulo its size would not.
func pick(seed Round, n int) int {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(seed))
	sum := sha256.Sum256(buf[:])
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}

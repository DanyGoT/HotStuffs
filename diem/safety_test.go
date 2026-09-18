package diem

import (
	"testing"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
)

// testN and testQuorum give a 4-replica group (f=1, quorum=2f+1=3), matching
// hotstuff.QuorumSize(testN).
const (
	testN      = 4
	testQuorum = 3
)

// safetyFixture bundles a Safety module with the ledger and block tree it was
// built over, so a test can reach into the ledger without re-deriving it.
type safetyFixture struct {
	safety *Safety
	ledger *MemLedger
	crypto Crypto
}

func newSafetyFixture(id ID) *safetyFixture {
	ledger := NewMemLedger()
	crypto := nocrypto.New(id, testN)
	tree := NewBlockTree(id, testQuorum, ledger, crypto)
	return &safetyFixture{
		safety: NewSafety(id, testQuorum, crypto, ledger, tree),
		ledger: ledger,
		crypto: crypto,
	}
}

// signAs signs digest as replica id. nocrypto never fails to sign.
func signAs(id ID, digest Hash) Signature {
	sig, _ := nocrypto.New(id, testN).Sign(digest)
	return sig
}

// makeTC builds a TC for round out of one timeout vote per entry in
// highQCRounds, signed by replicas 1..len(highQCRounds).
func makeTC(round Round, highQCRounds ...Round) *TC {
	tc := &TC{Round: round}
	for i, r := range highQCRounds {
		id := ID(i + 1)
		tc.Votes = append(tc.Votes, TimeoutVote{HighQCRound: r, Sig: signAs(id, TimeoutDigest(round, r))})
	}
	return tc
}

// makeQC builds a QC over voteInfo whose LedgerCommitInfo is correctly bound
// to it, signed by signerIDs.
func makeQC(voteInfo VoteInfo, commitStateID Hash, signerIDs ...ID) *QC {
	commit := LedgerCommitInfo{CommitStateID: commitStateID, VoteInfoHash: VoteInfoHash(voteInfo)}
	digest := LedgerCommitDigest(commit)
	sigs := make([]Signature, len(signerIDs))
	for i, id := range signerIDs {
		sigs[i] = signAs(id, digest)
	}
	return &QC{VoteInfo: voteInfo, LedgerCommitInfo: commit, Signatures: sigs}
}

func TestConsecutive(t *testing.T) {
	tests := []struct {
		name              string
		blockRound, round Round
		want              bool
	}{
		{"consecutive", 5, 4, true},
		{"gap", 5, 3, false},
		{"same round", 5, 5, false},
		{"genesis boundary", 1, 0, true},
		{"block round below", 3, 4, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := consecutive(tt.blockRound, tt.round); got != tt.want {
				t.Errorf("consecutive(%d, %d) = %v, want %v", tt.blockRound, tt.round, got, tt.want)
			}
		})
	}
}

func TestSafeToExtend(t *testing.T) {
	f := newSafetyFixture(1)
	tests := []struct {
		name                string
		blockRound, qcRound Round
		tc                  *TC
		want                bool
	}{
		{"nil tc", 11, 5, nil, false},
		{"non-consecutive tc round", 12, 5, makeTC(10, 3, 4, 5), false},
		{"qc round below max high qc round", 11, 4, makeTC(10, 3, 4, 5), false},
		{"qc round at max high qc round", 11, 5, makeTC(10, 3, 4, 5), true},
		{"qc round above max high qc round", 11, 6, makeTC(10, 3, 4, 5), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.safety.safeToExtend(tt.blockRound, tt.qcRound, tt.tc); got != tt.want {
				t.Errorf("safeToExtend(%d, %d, tc) = %v, want %v", tt.blockRound, tt.qcRound, got, tt.want)
			}
		})
	}
}

func TestSafeToVote(t *testing.T) {
	tests := []struct {
		name             string
		highestVoteRound Round
		blockRound       Round
		qcRound          Round
		tc               *TC
		want             bool
	}{
		{"monotonic round rejected", 5, 5, 3, nil, false},
		{"must extend a smaller round", 0, 5, 5, nil, false},
		{"consecutive qc accepted", 0, 6, 5, nil, true},
		{"tc justifies the gap", 0, 11, 6, makeTC(10, 3, 4, 6), true},
		{"tc round not directly below block round rejected", 0, 11, 6, makeTC(9, 3, 4, 6), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSafetyFixture(1)
			f.safety.highestVoteRound = tt.highestVoteRound
			if got := f.safety.safeToVote(tt.blockRound, tt.qcRound, tt.tc); got != tt.want {
				t.Errorf("safeToVote(%d, %d, tc) = %v, want %v", tt.blockRound, tt.qcRound, got, tt.want)
			}
		})
	}
}

func TestSafeToTimeout(t *testing.T) {
	tests := []struct {
		name             string
		highestQCRound   Round
		highestVoteRound Round
		round            Round
		qcRound          Round
		tc               *TC
		want             bool
	}{
		{"qc round below highest qc round rejected", 5, 0, 10, 4, nil, false},
		{"highest-vote-round-1 boundary rejected", 0, 5, 4, 0, nil, false},
		{"above the boundary with a consecutive qc accepted", 0, 5, 5, 4, nil, true},
		{"highest vote round zero does not underflow: round 1 accepted", 0, 0, 1, 0, nil, true},
		{"highest vote round zero: round 0 itself still rejected", 0, 0, 0, 0, nil, false},
		{"consecutive qc accept path", 0, 0, 6, 5, nil, true},
		{"consecutive tc accept path", 0, 0, 11, 3, makeTC(10, 1, 2), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSafetyFixture(1)
			f.safety.highestQCRound = tt.highestQCRound
			f.safety.highestVoteRound = tt.highestVoteRound
			if got := f.safety.safeToTimeout(tt.round, tt.qcRound, tt.tc); got != tt.want {
				t.Errorf("safeToTimeout(%d, %d, tc) = %v, want %v", tt.round, tt.qcRound, got, tt.want)
			}
		})
	}
}

func TestCommitStateIDCandidate(t *testing.T) {
	t.Run("round gap returns zero", func(t *testing.T) {
		f := newSafetyFixture(1)
		qc := &QC{VoteInfo: VoteInfo{ID: GenesisBlock().ID(), Round: 0}}
		if got := f.safety.commitStateIDCandidate(5, qc); got != (Hash{}) {
			t.Errorf("commitStateIDCandidate = %x, want zero", got)
		}
	})

	t.Run("contiguous two-chain returns the parent's pending state", func(t *testing.T) {
		f := newSafetyFixture(1)
		parent := NewBlock(1, 1, [][]byte{[]byte("a")}, GenesisQC())
		state := f.ledger.Speculate(parent)
		qc := &QC{VoteInfo: VoteInfo{ID: parent.ID(), Round: parent.Round}}
		if got := f.safety.commitStateIDCandidate(2, qc); got != state {
			t.Errorf("commitStateIDCandidate = %x, want %x", got, state)
		}
	})

	t.Run("no pending state returns zero", func(t *testing.T) {
		f := newSafetyFixture(1)
		qc := &QC{VoteInfo: VoteInfo{ID: Hash{0xAA}, Round: 1}} // never speculated
		if got := f.safety.commitStateIDCandidate(2, qc); got != (Hash{}) {
			t.Errorf("commitStateIDCandidate = %x, want zero", got)
		}
	})
}

func TestMakeVote(t *testing.T) {
	t.Run("nil when the safety rules refuse", func(t *testing.T) {
		f := newSafetyFixture(1)
		f.safety.highestVoteRound = 5 // blocks round 1, which is not > 5
		b := NewBlock(1, 1, nil, GenesisQC())
		f.ledger.Speculate(b)
		if v := f.safety.MakeVote(b, nil); v != nil {
			t.Errorf("MakeVote = %+v, want nil", v)
		}
	})

	t.Run("nil when the ledger never executed the block", func(t *testing.T) {
		f := newSafetyFixture(1)
		b := NewBlock(1, 1, nil, GenesisQC())
		// b is never passed to Speculate, so PendingState(b.ID()) is false.
		if v := f.safety.MakeVote(b, nil); v != nil {
			t.Errorf("MakeVote = %+v, want nil", v)
		}
	})

	t.Run("success raises both counters and binds the commit info", func(t *testing.T) {
		f := newSafetyFixture(1)

		block1 := NewBlock(1, 1, [][]byte{[]byte("a")}, GenesisQC())
		state1 := f.ledger.Speculate(block1)
		voteInfo1 := VoteInfo{
			ID: block1.ID(), Round: 1,
			ParentID: GenesisBlock().ID(), ParentRound: 0,
			ExecStateID: state1,
		}
		qc1 := makeQC(voteInfo1, Hash{}, 1, 2, 3)

		block2 := NewBlock(1, 2, [][]byte{[]byte("b")}, qc1)
		f.ledger.Speculate(block2)

		vote := f.safety.MakeVote(block2, nil)
		if vote == nil {
			t.Fatal("MakeVote = nil, want a vote")
		}
		if f.safety.HighestVoteRound() != 2 {
			t.Errorf("HighestVoteRound = %d, want 2", f.safety.HighestVoteRound())
		}
		if f.safety.HighestQCRound() != 1 {
			t.Errorf("HighestQCRound = %d, want 1", f.safety.HighestQCRound())
		}
		if vote.LedgerCommitInfo.VoteInfoHash != VoteInfoHash(vote.VoteInfo) {
			t.Error("LedgerCommitInfo.VoteInfoHash does not match VoteInfoHash(vote.VoteInfo)")
		}
	})
}

func TestMakeTimeout(t *testing.T) {
	t.Run("nil when the safety rules refuse", func(t *testing.T) {
		f := newSafetyFixture(1)
		f.safety.highestQCRound = 10 // GenesisQC's round (0) is now below it
		if to := f.safety.MakeTimeout(1, GenesisQC(), nil); to != nil {
			t.Errorf("MakeTimeout = %+v, want nil", to)
		}
	})

	t.Run("success raises highestVoteRound and signs the timeout digest", func(t *testing.T) {
		f := newSafetyFixture(1)
		to := f.safety.MakeTimeout(1, GenesisQC(), nil)
		if to == nil {
			t.Fatal("MakeTimeout = nil, want a timeout")
		}
		if f.safety.HighestVoteRound() != 1 {
			t.Errorf("HighestVoteRound = %d, want 1", f.safety.HighestVoteRound())
		}
		digest := TimeoutDigest(to.Round, to.HighQC.Round())
		if !f.crypto.Verify(digest, to.Sig) {
			t.Error("timeout signature does not verify against TimeoutDigest(round, highQC.Round())")
		}
	})
}

func TestValidQC(t *testing.T) {
	f := newSafetyFixture(1)

	t.Run("nil is invalid", func(t *testing.T) {
		if f.safety.ValidQC(nil) {
			t.Error("ValidQC(nil) = true, want false")
		}
	})

	t.Run("genesis qc is valid", func(t *testing.T) {
		if !f.safety.ValidQC(GenesisQC()) {
			t.Error("ValidQC(GenesisQC()) = false, want true")
		}
	})

	t.Run("vote info not bound to the ledger commit info is rejected", func(t *testing.T) {
		voteInfo := VoteInfo{ID: GenesisBlock().ID(), Round: 1}
		qc := makeQC(voteInfo, Hash{}, 1, 2, 3)
		qc.VoteInfo.Round = 2 // tamper after the commit hash was computed over Round: 1
		if f.safety.ValidQC(qc) {
			t.Error("ValidQC = true for a QC whose VoteInfo does not match its LedgerCommitInfo hash")
		}
	})

	t.Run("too few signatures is rejected", func(t *testing.T) {
		voteInfo := VoteInfo{ID: GenesisBlock().ID(), Round: 1}
		qc := makeQC(voteInfo, Hash{}, 1, 2) // quorum is 3
		if f.safety.ValidQC(qc) {
			t.Error("ValidQC = true below quorum, want false")
		}
	})
}

func TestValidTC(t *testing.T) {
	f := newSafetyFixture(1)

	t.Run("nil is valid", func(t *testing.T) {
		if !f.safety.ValidTC(nil) {
			t.Error("ValidTC(nil) = false, want true")
		}
	})

	t.Run("duplicate signers rejected", func(t *testing.T) {
		tc := &TC{Round: 5, Votes: []TimeoutVote{
			{HighQCRound: 3, Sig: signAs(1, TimeoutDigest(5, 3))},
			{HighQCRound: 3, Sig: signAs(1, TimeoutDigest(5, 3))},
			{HighQCRound: 4, Sig: signAs(2, TimeoutDigest(5, 4))},
		}}
		if f.safety.ValidTC(tc) {
			t.Error("ValidTC = true with a duplicate signer, want false")
		}
	})

	t.Run("wrong-digest signature rejected", func(t *testing.T) {
		tc := &TC{Round: 5, Votes: []TimeoutVote{
			{HighQCRound: 3, Sig: signAs(1, TimeoutDigest(5, 3))},
			{HighQCRound: 4, Sig: signAs(2, TimeoutDigest(99, 4))}, // signed a different round
			{HighQCRound: 5, Sig: signAs(3, TimeoutDigest(5, 5))},
		}}
		if f.safety.ValidTC(tc) {
			t.Error("ValidTC = true with a signature over the wrong digest, want false")
		}
	})

	t.Run("below quorum rejected", func(t *testing.T) {
		tc := makeTC(5, 3, 4) // 2 signers, quorum is 3
		if f.safety.ValidTC(tc) {
			t.Error("ValidTC = true below quorum, want false")
		}
	})

	t.Run("quorum of distinct signers accepted", func(t *testing.T) {
		tc := makeTC(5, 3, 4, 5)
		if !f.safety.ValidTC(tc) {
			t.Error("ValidTC = false for a valid quorum, want true")
		}
	})
}

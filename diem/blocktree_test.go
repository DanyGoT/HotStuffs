package diem

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
)

// newTestTree returns a block tree over a fresh ledger, at the group size and
// quorum safety_test.go's fixtures use.
func newTestTree(id ID) (*BlockTree, *MemLedger) {
	ledger := NewMemLedger()
	tree := NewBlockTree(id, testQuorum, ledger, nocrypto.New(id, testN))
	return tree, ledger
}

// castVote builds a VoteMsg signed by sender, the way Safety.MakeVote would,
// without going through Safety's own rules: ProcessVote is what is under test
// here.
func castVote(sender ID, voteInfo VoteInfo, commit LedgerCommitInfo) *VoteMsg {
	return &VoteMsg{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		Sender:           sender,
		Sig:              signAs(sender, LedgerCommitDigest(commit)),
	}
}

// committingSetup returns a tree that has already processed a QC committing
// b1 (round 1) via a certificate over b2 (round 2). Tests that need a
// non-genesis HighCommitQC already in place build on this.
func committingSetup(id ID) (tree *BlockTree, ledger *MemLedger, b1, b2 *Block, qc2 *QC) {
	tree, ledger = newTestTree(id)

	b1 = NewBlock(id, 1, nil, GenesisQC())
	tree.ExecuteAndInsert(b1)

	qc1 := &QC{VoteInfo: VoteInfo{ID: b1.ID(), Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}}
	b2 = NewBlock(id, 2, nil, qc1)
	tree.ExecuteAndInsert(b2)

	qc2 = &QC{
		VoteInfo:         VoteInfo{ID: b2.ID(), Round: 2, ParentID: b1.ID(), ParentRound: 1},
		LedgerCommitInfo: LedgerCommitInfo{CommitStateID: Hash{0x99}},
	}
	tree.ProcessQC(qc2)
	return
}

func TestNewBlockTreeGenesisCertificates(t *testing.T) {
	tree, _ := newTestTree(1)
	if tree.HighQC() != GenesisQC() {
		t.Errorf("HighQC = %+v, want GenesisQC", tree.HighQC())
	}
	if tree.HighCommitQC() != GenesisQC() {
		t.Errorf("HighCommitQC = %+v, want GenesisQC", tree.HighCommitQC())
	}
}

func TestProcessQCNilIsNoop(t *testing.T) {
	tree, _ := newTestTree(1)
	tree.ProcessQC(nil)
	if tree.HighQC() != GenesisQC() || tree.HighCommitQC() != GenesisQC() {
		t.Fatal("ProcessQC(nil) changed the tree's certificates")
	}
}

func TestProcessQCNonCommittingRaisesHighQCOnly(t *testing.T) {
	tree, _ := newTestTree(1)
	qc := &QC{VoteInfo: VoteInfo{ID: Hash{0x01}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}}

	tree.ProcessQC(qc)

	if tree.HighQC() != qc {
		t.Error("HighQC was not raised to the new QC")
	}
	if tree.HighCommitQC() != GenesisQC() {
		t.Error("HighCommitQC moved on a QC that commits nothing")
	}
}

func TestProcessQCCommittingCommitsParentAndRaisesHighCommitQC(t *testing.T) {
	tree, ledger, b1, b2, qc2 := committingSetup(1)

	if _, ok := ledger.CommittedBlock(b1.ID()); !ok {
		t.Fatal("ProcessQC did not commit the QC's parent")
	}
	if tree.HighCommitQC() != qc2 {
		t.Error("HighCommitQC was not raised to the committing QC")
	}
	if tree.HighQC() != qc2 {
		t.Error("HighQC was not raised")
	}
	if _, ok := tree.Block(b1.ID()); !ok {
		t.Error("the new root was pruned from the pending tree")
	}
	if _, ok := tree.Block(b2.ID()); !ok {
		t.Error("the block above the new root was pruned")
	}
}

func TestProcessQCOlderNeverLowersHighQC(t *testing.T) {
	tree, _, _, _, qc2 := committingSetup(1)

	tree.ProcessQC(&QC{VoteInfo: VoteInfo{ID: Hash{0x01}, Round: 1}})

	if tree.HighQC() != qc2 {
		t.Error("an older QC lowered HighQC")
	}
}

func TestProcessQCOlderNeverLowersHighCommitQC(t *testing.T) {
	tree, _, _, _, qc2 := committingSetup(1)

	tree.ProcessQC(&QC{VoteInfo: VoteInfo{ID: Hash{0x02}, Round: 1}})

	if tree.HighCommitQC() != qc2 {
		t.Error("an older QC lowered HighCommitQC")
	}
}

func TestExecuteAndInsertMakesBlockRetrievable(t *testing.T) {
	tree, _ := newTestTree(1)
	b := NewBlock(1, 1, [][]byte{{0x07}}, GenesisQC())

	tree.ExecuteAndInsert(b)

	got, ok := tree.Block(b.ID())
	if !ok || got != b {
		t.Fatalf("Block(id) = (%+v, %v), want (%+v, true)", got, ok, b)
	}
}

func TestProcessVoteBelowQuorumReturnsNil(t *testing.T) {
	tree, _ := newTestTree(1)
	voteInfo := VoteInfo{ID: Hash{0x10}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}

	if qc := tree.ProcessVote(castVote(1, voteInfo, commit)); qc != nil {
		t.Fatal("a QC formed on 1 vote, quorum is 3")
	}
	if qc := tree.ProcessVote(castVote(2, voteInfo, commit)); qc != nil {
		t.Fatal("a QC formed on 2 votes, quorum is 3")
	}
}

func TestProcessVoteAtQuorumReturnsQC(t *testing.T) {
	tree, _ := newTestTree(1)
	voteInfo := VoteInfo{ID: Hash{0x11}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}

	tree.ProcessVote(castVote(1, voteInfo, commit))
	tree.ProcessVote(castVote(2, voteInfo, commit))
	qc := tree.ProcessVote(castVote(3, voteInfo, commit))

	if qc == nil {
		t.Fatal("no QC at quorum")
	}
	if len(qc.Signatures) != testQuorum {
		t.Fatalf("QC has %d signatures, want %d", len(qc.Signatures), testQuorum)
	}
}

// TestProcessVoteDuplicateSenderDoesNotCountTwice pins the dedup ProcessVote
// does over the paper's process_vote: a set union of raw signatures would not
// collapse two signatures by the same sender under a randomised scheme, which
// would let one sender reach quorum alone.
func TestProcessVoteDuplicateSenderDoesNotCountTwice(t *testing.T) {
	tree, _ := newTestTree(1)
	voteInfo := VoteInfo{ID: Hash{0x12}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}

	for range 3 {
		if qc := tree.ProcessVote(castVote(1, voteInfo, commit)); qc != nil {
			t.Fatal("repeated votes from one sender produced a QC alone")
		}
	}
	if qc := tree.ProcessVote(castVote(2, voteInfo, commit)); qc != nil {
		t.Fatal("a QC formed with only 2 distinct signers, quorum is 3")
	}
	if qc := tree.ProcessVote(castVote(3, voteInfo, commit)); qc == nil {
		t.Fatal("no QC formed once a 3rd distinct signer voted")
	}
}

// unsignableCrypto verifies normally but cannot produce a signature, which
// isolates the one path where the quorum is complete and this replica still has
// nothing to author the certificate with.
type unsignableCrypto struct{ Crypto }

func (unsignableCrypto) Sign(Hash) (Signature, error) { return Signature{}, errors.New("no key") }

// TestProcessVoteWithoutAnAuthorSignatureEmitsNoQC pins the consequence of the
// author signature being verified on receipt: a certificate this replica cannot
// sign is one no receiver would accept, so it is not worth emitting.
func TestProcessVoteWithoutAnAuthorSignatureEmitsNoQC(t *testing.T) {
	ledger := NewMemLedger()
	tree := NewBlockTree(1, testQuorum, ledger, unsignableCrypto{nocrypto.New(1, testN)})
	voteInfo := VoteInfo{ID: Hash{0x15}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}

	for _, sender := range []ID{1, 2, 3} {
		if qc := tree.ProcessVote(castVote(sender, voteInfo, commit)); qc != nil {
			t.Fatal("emitted a QC this replica could not author")
		}
	}
}

// TestProcessVoteBoundsBucketsPerSignerPerRound pins the bound a digest key
// alone cannot give. Votes bucket on the LedgerCommitInfo digest, and its
// sender picks every field that feeds it: varying ExecStateID mints a fresh,
// individually valid vote per message, so one sender opens one bucket per
// message and the dedup inside a bucket never sees it. An honest replica votes
// at most once per round — safeToVote requires blockRound > highestVoteRound,
// which never decreases — so one slot per (round, signer) is all that can ever
// be legitimate.
func TestProcessVoteBoundsBucketsPerSignerPerRound(t *testing.T) {
	tree, _ := newTestTree(1)
	const round Round = 1

	for i := range 32 {
		voteInfo := VoteInfo{
			ID:          Hash{0x16},
			Round:       round,
			ParentID:    GenesisBlock().ID(),
			ExecStateID: Hash{byte(i)},
		}
		commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}
		if qc := tree.ProcessVote(castVote(2, voteInfo, commit)); qc != nil {
			t.Fatal("one sender reached quorum alone")
		}
	}
	if got := len(tree.votes); got != 1 {
		t.Errorf("one sender opened %d vote buckets in round %d, want 1", got, round)
	}
}

func TestProcessVoteDisagreeingLedgerCommitInfoDoesNotCombine(t *testing.T) {
	tree, _ := newTestTree(1)
	voteInfo := VoteInfo{ID: Hash{0x13}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	commitA := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}
	commitB := LedgerCommitInfo{CommitStateID: Hash{0x01}, VoteInfoHash: VoteInfoHash(voteInfo)}

	tree.ProcessVote(castVote(1, voteInfo, commitA))
	tree.ProcessVote(castVote(2, voteInfo, commitA))
	tree.ProcessVote(castVote(3, voteInfo, commitB))
	if qc := tree.ProcessVote(castVote(4, voteInfo, commitB)); qc != nil {
		t.Fatal("votes disagreeing on LedgerCommitInfo combined into one quorum")
	}
}

func TestProcessVoteQCSignaturesSortedBySigner(t *testing.T) {
	tree, _ := newTestTree(1)
	voteInfo := VoteInfo{ID: Hash{0x14}, Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	commit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(voteInfo)}

	tree.ProcessVote(castVote(3, voteInfo, commit))
	tree.ProcessVote(castVote(1, voteInfo, commit))
	qc := tree.ProcessVote(castVote(2, voteInfo, commit))

	if qc == nil {
		t.Fatal("no QC at quorum")
	}
	want := []ID{1, 2, 3}
	for i, sig := range qc.Signatures {
		if sig.Signer != want[i] {
			t.Fatalf("Signatures[%d].Signer = %d, want %d (signer order %v)", i, sig.Signer, want[i], signerOrder(qc))
		}
	}
}

func signerOrder(qc *QC) []ID {
	out := make([]ID, len(qc.Signatures))
	for i, s := range qc.Signatures {
		out[i] = s.Signer
	}
	return out
}

func TestGenerateBlockOverHighQC(t *testing.T) {
	tree, _ := newTestTree(1)
	qc := &QC{VoteInfo: VoteInfo{ID: Hash{0x20}, Round: 3}}
	tree.ProcessQC(qc)

	payload := [][]byte{{0x01}, {0x02}}
	b := tree.GenerateBlock(payload, 4)

	if b.Author != 1 {
		t.Errorf("Author = %d, want 1", b.Author)
	}
	if b.Round != 4 {
		t.Errorf("Round = %d, want 4", b.Round)
	}
	if !slices.EqualFunc(b.Payload, payload, bytes.Equal) {
		t.Errorf("Payload = %v, want %v", b.Payload, payload)
	}
	if b.QC != qc {
		t.Errorf("block built over %+v, want HighQC %+v", b.QC, qc)
	}
}

// TestProcessQCCommitPrunesBelowRootAndAbandonedBranches exercises the last
// half of process_qc's prune step: the new root's round drops both its own
// ancestry and any sibling branch that never got certified, plus the vote
// buckets sitting at or below that round.
func TestProcessQCCommitPrunesBelowRootAndAbandonedBranches(t *testing.T) {
	tree, ledger := newTestTree(1)

	b1 := NewBlock(1, 1, nil, GenesisQC())
	tree.ExecuteAndInsert(b1)

	// An abandoned fork: another child of genesis that never gets certified.
	fork := NewBlock(1, 1, [][]byte{{0xFF}}, GenesisQC())
	tree.ExecuteAndInsert(fork)

	qc1 := &QC{VoteInfo: VoteInfo{ID: b1.ID(), Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}}
	b2 := NewBlock(1, 2, nil, qc1)
	tree.ExecuteAndInsert(b2)

	// A vote bucket at round 1 that never reaches quorum; it must be dropped
	// along with the pruned round.
	forkVoteInfo := VoteInfo{ID: fork.ID(), Round: 1, ParentID: GenesisBlock().ID(), ParentRound: 0}
	forkCommit := LedgerCommitInfo{VoteInfoHash: VoteInfoHash(forkVoteInfo)}
	tree.ProcessVote(castVote(1, forkVoteInfo, forkCommit))

	qc2 := &QC{
		VoteInfo:         VoteInfo{ID: b2.ID(), Round: 2, ParentID: b1.ID(), ParentRound: 1},
		LedgerCommitInfo: LedgerCommitInfo{CommitStateID: Hash{0x88}},
	}
	tree.ProcessQC(qc2)

	if _, ok := tree.Block(fork.ID()); ok {
		t.Error("the abandoned branch survived pruning")
	}
	if _, ok := tree.Block(b1.ID()); !ok {
		t.Error("the new root was pruned")
	}
	if _, ok := tree.Block(b2.ID()); !ok {
		t.Error("the block above the new root was pruned")
	}
	if _, ok := ledger.CommittedBlock(b1.ID()); !ok {
		t.Error("the new root was never committed")
	}
	if _, ok := tree.votes[LedgerCommitDigest(forkCommit)]; ok {
		t.Error("a vote bucket at or below the new root's round survived pruning")
	}
}

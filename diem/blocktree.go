package diem

import (
	"cmp"
	"slices"
)

// BlockTree is the paper's Block-tree module (3.3): the tree of blocks pending
// commitment, the votes collected on them, and the two highest certificates.
type BlockTree struct {
	id     ID
	quorum int
	ledger *MemLedger
	crypto Crypto

	pending map[Hash]*Block
	votes   map[Hash]*voteBucket
	voters  map[voterKey]struct{}

	highQC       *QC
	highCommitQC *QC
}

// voteBucket accumulates the votes that agree on one LedgerCommitInfo. Votes
// are keyed by its digest rather than by block id: agreeing on it means
// agreeing on the block, its parent and the speculated execution state at
// once, since the VoteInfo hash is inside it.
type voteBucket struct {
	voteInfo VoteInfo
	commit   LedgerCommitInfo
	sigs     []Signature
}

// voterKey is one replica's vote slot for a round. An honest replica votes at
// most once per round — safeToVote requires the block's round to exceed
// highest_vote_round, which never decreases — so one entry per (round, signer)
// is all that can ever be legitimate. Enforcing it across buckets is what
// bounds the accumulator: the bucket key is a digest over fields its sender
// chooses, so a signer who varies one of them opens a bucket per message
// without ever repeating itself inside one.
type voterKey struct {
	round  Round
	signer ID
}

// NewBlockTree returns a block tree holding only the genesis certificate.
func NewBlockTree(id ID, quorum int, ledger *MemLedger, crypto Crypto) *BlockTree {
	return &BlockTree{
		id:           id,
		quorum:       quorum,
		ledger:       ledger,
		crypto:       crypto,
		pending:      map[Hash]*Block{},
		votes:        map[Hash]*voteBucket{},
		voters:       map[voterKey]struct{}{},
		highQC:       genesisQC,
		highCommitQC: genesisQC,
	}
}

// HighQC is the highest certificate seen. New proposals extend it.
func (t *BlockTree) HighQC() *QC { return t.highQC }

// HighCommitQC is the highest certificate that committed something. It rides
// on every outgoing message so a lagging replica catches up on commits.
func (t *BlockTree) HighCommitQC() *QC { return t.highCommitQC }

// Block returns a pending block by id. The protocol never calls it: the paper's
// pending_block_tree (3.3) is read only by prune. It is kept as the one read
// path into the tree — what a block-sync responder would serve from, and what
// the pruning tests assert against.
func (t *BlockTree) Block(id Hash) (*Block, bool) {
	b, ok := t.pending[id]
	return b, ok
}

// ProcessQC is the paper's process_qc. A certificate whose LedgerCommitInfo
// names a committed state commits that block's *parent*: the vote was cast on
// a block whose round directly follows its parent's, so a quorum over it is a
// quorum over the contiguous 2-chain ending at the parent.
func (t *BlockTree) ProcessQC(qc *QC) {
	if qc == nil {
		return
	}
	if qc.LedgerCommitInfo.Commits() {
		t.ledger.Commit(qc.VoteInfo.ParentID)
		t.prune(qc.VoteInfo.ParentID, qc.VoteInfo.ParentRound)
		t.highCommitQC = higher(qc, t.highCommitQC)
	}
	t.highQC = higher(qc, t.highQC)
}

// ExecuteAndInsert speculatively executes b and adds it to the pending tree.
func (t *BlockTree) ExecuteAndInsert(b *Block) {
	t.ledger.Speculate(b)
	t.pending[b.ID()] = b
}

// ProcessVote accumulates v and returns the certificate it completed, or nil.
//
// The paper writes the accumulator as a set union over signatures. With a
// randomised signature scheme two signatures by one replica differ byte for
// byte, so the union would not deduplicate and a single sender could reach the
// quorum alone. Deduplication is therefore by signer.
func (t *BlockTree) ProcessVote(v *VoteMsg) *QC {
	t.ProcessQC(v.HighCommitQC)

	vk := voterKey{round: v.VoteInfo.Round, signer: v.Sender}
	if _, voted := t.voters[vk]; voted {
		return nil
	}
	idx := LedgerCommitDigest(v.LedgerCommitInfo)
	b := t.votes[idx]
	if b == nil {
		b = &voteBucket{voteInfo: v.VoteInfo, commit: v.LedgerCommitInfo}
		t.votes[idx] = b
	}
	t.voters[vk] = struct{}{}
	b.sigs = append(b.sigs, v.Sig)
	if len(b.sigs) < t.quorum {
		return nil
	}

	sigs := canonical(b.sigs)
	// The author signature certifies nothing the quorum does not. It names who
	// assembled this particular set, which is what an equivocating aggregator
	// can then be held to. Every receiver checks it, so a certificate that
	// cannot carry one is a certificate nobody would accept.
	authorSig, err := t.crypto.Sign(qcSigsDigest(sigs))
	if err != nil {
		return nil
	}
	delete(t.votes, idx) // the certificate exists; further votes for it are dead weight
	return &QC{
		VoteInfo:         b.voteInfo,
		LedgerCommitInfo: b.commit,
		Signatures:       sigs,
		Author:           t.id,
		AuthorSig:        authorSig,
	}
}

// GenerateBlock is the paper's generate_block: a block for round over the
// highest certificate known, which is what keeps the chain extending the
// longest certified branch.
func (t *BlockTree) GenerateBlock(txns [][]byte, round Round) *Block {
	return NewBlock(t.id, round, txns, t.highQC)
}

// prune makes rootID the new root of the pending tree. Ancestors and forks
// below it can no longer be committed, and the votes gathered for them can no
// longer complete a useful certificate.
//
// rootRound comes from the certificate rather than from a lookup: the root may
// already have been pruned by an earlier commit, and the QC carries its round.
func (t *BlockTree) prune(rootID Hash, rootRound Round) {
	for id, b := range t.pending {
		if b.Round <= rootRound && id != rootID {
			delete(t.pending, id)
		}
	}
	// A block survives only while its parent does, so dropping orphans to a
	// fixpoint removes whole abandoned branches without needing child links.
	for changed := true; changed; {
		changed = false
		for id, b := range t.pending {
			parent := b.ParentID()
			if id == rootID || parent == rootID {
				continue
			}
			if _, ok := t.pending[parent]; !ok {
				delete(t.pending, id)
				changed = true
			}
		}
	}
	for idx, b := range t.votes {
		if b.voteInfo.Round <= rootRound {
			delete(t.votes, idx)
		}
	}
	for vk := range t.voters {
		if vk.round <= rootRound {
			delete(t.voters, vk)
		}
	}
}

// canonical copies sigs into the strictly increasing signer order every
// certificate must be in, so one quorum has one wire form — and so a block id,
// which covers the signature set, is the same on every replica.
func canonical(sigs []Signature) []Signature {
	out := slices.Clone(sigs)
	slices.SortFunc(out, func(a, b Signature) int { return cmp.Compare(a.Signer, b.Signer) })
	return out
}

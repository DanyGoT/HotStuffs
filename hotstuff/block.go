package hotstuff

// Block is immutable once built; its hash is cached.
type Block struct {
	parent   Hash
	view     View
	proposer ID
	qc       QuorumCert
	cmds     [][]byte
	hash     Hash
}

// NewBlock builds a block and caches its digest.
func NewBlock(parent Hash, view View, proposer ID, qc QuorumCert, cmds [][]byte) *Block {
	b := &Block{
		parent:   parent,
		view:     view,
		proposer: proposer,
		qc:       qc,
		cmds:     cmds,
	}
	b.hash = blockDigest(parent, view, proposer, qc, cmds)
	return b
}

// Hash is the cached block digest.
func (b *Block) Hash() Hash { return b.hash }

// Parent is the hash of the block this one extends.
func (b *Block) Parent() Hash { return b.parent }

// View is the view this block was proposed in.
func (b *Block) View() View { return b.view }

// Proposer is the ID of the block's leader.
func (b *Block) Proposer() ID { return b.proposer }

// QC is the quorum certificate this block carries.
func (b *Block) QC() QuorumCert { return b.qc }

// Cmds are the commands this block commits.
func (b *Block) Cmds() [][]byte { return b.cmds }

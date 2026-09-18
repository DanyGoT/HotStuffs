package diem

// The genesis block and the certificate for it are hardcoded identically by
// every replica, which is what gives round 1 a parent to extend.
//
// Two objects are needed, not one. The genesis block must carry a QC, since
// its id covers one, but no certificate can name the genesis block before its
// id exists. So the block carries an empty seed certificate that certifies
// nothing, and GenesisQC — the one round-1 proposals extend — certifies the
// block that resulted.
var (
	genesisSeedQC = &QC{}
	genesisBlock  = NewBlock(0, 0, nil, genesisSeedQC)
	genesisQC     = &QC{VoteInfo: VoteInfo{ID: genesisBlock.ID()}}
)

// GenesisBlock returns the same immutable block on every call.
func GenesisBlock() *Block { return genesisBlock }

// GenesisQC returns the certificate a round-1 proposal extends. Its signature
// set is empty: genesis is trusted, not certified.
func GenesisQC() *QC { return genesisQC }

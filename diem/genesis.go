package diem

import "github.com/DanyGoT/HotStuffs/proto/diempb"

// The genesis block and the certificate for it are hardcoded identically by
// every replica, which is what gives round 1 a parent to extend.
//
// Two objects are needed, not one. The genesis block must carry a QC, since
// its id covers one, but no certificate can name the genesis block before its
// id exists. So the block carries an empty seed certificate that certifies
// nothing, and GenesisQC — the one round-1 proposals extend — certifies the
// block that resulted.
//
// Both are all-zero but for the id, with every hash field at its full length:
// genesis travels on the wire like any certificate and passes the same check.
var (
	genesisSeedQC = zeroQC(zeroHash[:])
	genesisBlock  = NewBlock(0, 0, nil, genesisSeedQC)
	genesisQC     = zeroQC(genesisBlock.GetId())
)

func zeroQC(id []byte) *diempb.QuorumCert {
	return diempb.QuorumCert_builder{
		VoteInfo: diempb.VoteInfo_builder{
			Id:          id,
			ParentId:    zeroHash[:],
			ExecStateId: zeroHash[:],
		}.Build(),
		LedgerCommitInfo: diempb.LedgerCommitInfo_builder{
			CommitStateId: zeroHash[:],
			VoteInfoHash:  zeroHash[:],
		}.Build(),
	}.Build()
}

// GenesisBlock returns the same immutable block on every call.
func GenesisBlock() *diempb.Block { return genesisBlock }

// GenesisQC returns the certificate a round-1 proposal extends. Its signature
// set is empty: genesis is trusted, not certified.
func GenesisQC() *diempb.QuorumCert { return genesisQC }

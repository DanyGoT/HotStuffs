// Package diem implements the DiemBFT v4 pseudocode of the paper's Section 3,
// one file per module: Ledger (3.2), Block-tree (3.3), Safety (3.4), Pacemaker
// (3.5), LeaderElection (3.7) and Main (3.1) in core.go. MemPool (3.6) is an
// interface in seams.go.
// It commits on a contiguous 2-chain and signs a LedgerCommitInfo.
//
// It works directly on the generated diempb messages, which are read-only once
// built. Rounds are uint64 and replica ids uint32, as on the wire; hashes are
// 32-byte slices, keyed in maps by string(h) and compared with bytes.Equal.
package diem

import "github.com/DanyGoT/diembft/proto/diempb"

// zeroHash is the paper's bottom: a LedgerCommitInfo carrying it as its
// CommitStateId commits nothing.
var zeroHash [hashLen]byte

// NewBlock builds a block and fills its id, the digest the core trusts from
// then on.
func NewBlock(author uint32, round uint64, payload [][]byte, qc *diempb.QuorumCert) *diempb.Block {
	b := diempb.Block_builder{
		Author:  author,
		Round:   round,
		Payload: payload,
		Qc:      qc,
	}.Build()
	b.SetId(b.ComputeID())
	return b
}

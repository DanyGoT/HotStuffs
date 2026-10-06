package diem

import "github.com/DanyGoT/HotStuffs/proto/diempb"

// hashOf is a full-length hash whose leading bytes are b.
func hashOf(b ...byte) []byte {
	out := make([]byte, hashLen)
	copy(out, b)
	return out
}

// voteInfo builds a VoteInfo with a zero exec state. A nil id or parent is the
// zero hash.
func voteInfo(id []byte, round uint64, parent []byte, parentRound uint64) *diempb.VoteInfo {
	return diempb.VoteInfo_builder{
		Id:          orZero(id),
		Round:       round,
		ParentId:    orZero(parent),
		ParentRound: parentRound,
		ExecStateId: zeroHash[:],
	}.Build()
}

// commitInfo builds a LedgerCommitInfo over vi that commits commitState; a nil
// commitState is the paper's bottom.
func commitInfo(commitState []byte, vi *diempb.VoteInfo) *diempb.LedgerCommitInfo {
	return diempb.LedgerCommitInfo_builder{
		CommitStateId: orZero(commitState),
		VoteInfoHash:  VoteInfoHash(vi),
	}.Build()
}

// bareQC is an unsigned certificate for round, over the block id.
func bareQC(id []byte, round uint64) *diempb.QuorumCert {
	return qcWith(voteInfo(id, round, nil, 0), nil)
}

// qcWith is an unsigned certificate over vi whose commit info commits
// commitState.
func qcWith(vi *diempb.VoteInfo, commitState []byte) *diempb.QuorumCert {
	return diempb.QuorumCert_builder{
		VoteInfo:         vi,
		LedgerCommitInfo: commitInfo(commitState, vi),
	}.Build()
}

// sigs builds signatures with the given signers and an empty body.
func sigs(signers ...uint32) []*diempb.Signature {
	out := make([]*diempb.Signature, len(signers))
	for i, s := range signers {
		out[i] = diempb.Signature_builder{Signer: s}.Build()
	}
	return out
}

func orZero(h []byte) []byte {
	if h == nil {
		return zeroHash[:]
	}
	return h
}

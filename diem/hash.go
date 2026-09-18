package diem

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// Domain tags keep the four things a replica signs apart: a vote signature can
// never verify as a timeout signature, nor either as a block id. Each digest
// starts with a distinct byte.
const (
	domainBlock        = 0x01
	domainVoteInfo     = 0x02
	domainLedgerCommit = 0x03
	domainTimeout      = 0x04
	domainQCSigs       = 0x05
	domainState        = 0x06
)

// hash.Hash.Write never returns an error, so these helpers have none to return.
func writeUint64(h hash.Hash, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	h.Write(buf[:])
}

func writeUint32(h hash.Hash, v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	h.Write(buf[:])
}

func writeBytes(h hash.Hash, b []byte) {
	writeUint64(h, uint64(len(b)))
	h.Write(b)
}

func writeSigs(h hash.Hash, sigs []Signature) {
	writeUint64(h, uint64(len(sigs)))
	for _, s := range sigs {
		writeUint32(h, uint32(s.Signer))
		writeBytes(h, s.Data)
	}
}

// blockID is the paper's
// hash(author || round || payload || qc.vote_info.id || qc.signatures).
//
// The signature set is inside the id, which is what makes the voters for a
// committed round uniquely determined by the chain: two leaders that certify
// the same parent with different quorums produce different blocks. That is the
// opposite of the choice package hotstuff makes, where the block hash covers
// only the QC's view and certified hash.
func blockID(author ID, round Round, payload [][]byte, qc *QC) Hash {
	h := sha256.New()
	h.Write([]byte{domainBlock})
	writeUint32(h, uint32(author))
	writeUint64(h, uint64(round))
	writeUint64(h, uint64(len(payload)))
	for _, p := range payload {
		writeBytes(h, p)
	}
	parent := qc.VoteInfo.ID
	h.Write(parent[:])
	writeSigs(h, qc.Signatures)
	return Hash(h.Sum(nil))
}

// VoteInfoHash is the digest a LedgerCommitInfo binds its vote to.
func VoteInfoHash(v VoteInfo) Hash {
	h := sha256.New()
	h.Write([]byte{domainVoteInfo})
	h.Write(v.ID[:])
	writeUint64(h, uint64(v.Round))
	h.Write(v.ParentID[:])
	writeUint64(h, uint64(v.ParentRound))
	h.Write(v.ExecStateID[:])
	return Hash(h.Sum(nil))
}

// LedgerCommitDigest is what a vote signature covers, and so also the key
// votes are aggregated under: two votes that agree on it agree on everything
// that matters, the VoteInfo included, since its hash is inside.
func LedgerCommitDigest(l LedgerCommitInfo) Hash {
	h := sha256.New()
	h.Write([]byte{domainLedgerCommit})
	h.Write(l.CommitStateID[:])
	h.Write(l.VoteInfoHash[:])
	return Hash(h.Sum(nil))
}

// TimeoutDigest is what a timeout signature covers: the round abandoned and
// the signer's own highest certified round. Both are needed, because a TC's
// safe-to-extend check reads the reported rounds back out.
func TimeoutDigest(round, highQCRound Round) Hash {
	h := sha256.New()
	h.Write([]byte{domainTimeout})
	writeUint64(h, uint64(round))
	writeUint64(h, uint64(highQCRound))
	return Hash(h.Sum(nil))
}

// qcSigsDigest is what a QC's author signature covers.
func qcSigsDigest(sigs []Signature) Hash {
	h := sha256.New()
	h.Write([]byte{domainQCSigs})
	writeSigs(h, sigs)
	return Hash(h.Sum(nil))
}

// ExecuteHash is the default speculative execution: a hash chain over the
// previous state and the payload. It is a stand-in for a VM, and it is enough
// for the property DiemBFT actually needs from execution — that honest
// replicas agree on the resulting state id and a diverging one does not.
func ExecuteHash(prev Hash, payload [][]byte) Hash {
	h := sha256.New()
	h.Write([]byte{domainState})
	h.Write(prev[:])
	writeUint64(h, uint64(len(payload)))
	for _, p := range payload {
		writeBytes(h, p)
	}
	return Hash(h.Sum(nil))
}

package diempb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// Domain tags keep the things a replica signs and hashes apart: a vote signature can
// never verify as a timeout signature, nor either as a block id. Each digest
// starts with a distinct byte. 0x06 is taken by diem's ExecuteHash.
const (
	domainBlock        = 0x01
	domainVoteInfo     = 0x02
	domainLedgerCommit = 0x03
	domainTimeout      = 0x04
	domainQCSigs       = 0x05
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

func writeSigs(h hash.Hash, sigs []*Signature) {
	writeUint64(h, uint64(len(sigs)))
	for _, s := range sigs {
		writeUint32(h, s.GetSigner())
		writeBytes(h, s.GetSig())
	}
}

// ComputeID is the paper's
// hash(author || round || payload || qc.vote_info.id || qc.signatures),
// recomputed from b's fields; it ignores the id b carries.
//
// The signature set is inside the id, which is what makes the voters for a
// committed round uniquely determined by the chain: two leaders that certify
// the same parent with different quorums produce different blocks.
func (b *Block) ComputeID() []byte {
	h := sha256.New()
	h.Write([]byte{domainBlock})
	writeUint32(h, b.GetAuthor())
	writeUint64(h, b.GetRound())
	writeUint64(h, uint64(len(b.GetPayload())))
	for _, p := range b.GetPayload() {
		writeBytes(h, p)
	}
	h.Write(b.GetQc().BlockID())
	writeSigs(h, b.GetQc().GetSignatures())
	return h.Sum(nil)
}

// ValidID reports whether the id b carries is the one its fields hash to.
func (b *Block) ValidID() bool { return bytes.Equal(b.ComputeID(), b.GetId()) }

// Hash is the digest a LedgerCommitInfo binds its vote to.
func (v *VoteInfo) Hash() []byte {
	h := sha256.New()
	h.Write([]byte{domainVoteInfo})
	h.Write(v.GetId())
	writeUint64(h, v.GetRound())
	h.Write(v.GetParentId())
	writeUint64(h, v.GetParentRound())
	h.Write(v.GetExecStateId())
	return h.Sum(nil)
}

// Digest is what a vote signature covers, and so also the key votes are
// aggregated under: two votes that agree on it agree on everything that
// matters, the VoteInfo included, since its hash is inside.
func (l *LedgerCommitInfo) Digest() []byte {
	h := sha256.New()
	h.Write([]byte{domainLedgerCommit})
	h.Write(l.GetCommitStateId())
	h.Write(l.GetVoteInfoHash())
	return h.Sum(nil)
}

// SigsDigest is what a QC's author signature covers: its signature set, in
// the order it holds it.
func (qc *QuorumCert) SigsDigest() []byte {
	h := sha256.New()
	h.Write([]byte{domainQCSigs})
	writeSigs(h, qc.GetSignatures())
	return h.Sum(nil)
}

// TimeoutDigest is what a timeout signature covers: the round abandoned and
// the signer's own highest certified round. Both are needed, because a TC's
// safe-to-extend check reads the reported rounds back out. It takes rounds,
// not a message, because a TimeoutVote carries only the second.
func TimeoutDigest(round, highQCRound uint64) []byte {
	h := sha256.New()
	h.Write([]byte{domainTimeout})
	writeUint64(h, round)
	writeUint64(h, highQCRound)
	return h.Sum(nil)
}

package diem

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// hashLen is the size of every digest on the wire.
const hashLen = sha256.Size

// Domain tags keep the things a replica signs and hashes apart: a vote signature can
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

func writeSigs(h hash.Hash, sigs []*diempb.Signature) {
	writeUint64(h, uint64(len(sigs)))
	for _, s := range sigs {
		writeUint32(h, s.GetSigner())
		writeBytes(h, s.GetSig())
	}
}

// blockID is the paper's
// hash(author || round || payload || qc.vote_info.id || qc.signatures).
//
// The signature set is inside the id, which is what makes the voters for a
// committed round uniquely determined by the chain: two leaders that certify
// the same parent with different quorums produce different blocks.
func blockID(author uint32, round uint64, payload [][]byte, qc *diempb.QuorumCert) []byte {
	h := sha256.New()
	h.Write([]byte{domainBlock})
	writeUint32(h, author)
	writeUint64(h, round)
	writeUint64(h, uint64(len(payload)))
	for _, p := range payload {
		writeBytes(h, p)
	}
	h.Write(qc.GetVoteInfo().GetId())
	writeSigs(h, qc.GetSignatures())
	return h.Sum(nil)
}

// VoteInfoHash is the digest a LedgerCommitInfo binds its vote to.
func VoteInfoHash(v *diempb.VoteInfo) []byte {
	h := sha256.New()
	h.Write([]byte{domainVoteInfo})
	h.Write(v.GetId())
	writeUint64(h, v.GetRound())
	h.Write(v.GetParentId())
	writeUint64(h, v.GetParentRound())
	h.Write(v.GetExecStateId())
	return h.Sum(nil)
}

// LedgerCommitDigest is what a vote signature covers, and so also the key
// votes are aggregated under: two votes that agree on it agree on everything
// that matters, the VoteInfo included, since its hash is inside.
func LedgerCommitDigest(l *diempb.LedgerCommitInfo) []byte {
	h := sha256.New()
	h.Write([]byte{domainLedgerCommit})
	h.Write(l.GetCommitStateId())
	h.Write(l.GetVoteInfoHash())
	return h.Sum(nil)
}

// TimeoutDigest is what a timeout signature covers: the round abandoned and
// the signer's own highest certified round. Both are needed, because a TC's
// safe-to-extend check reads the reported rounds back out.
func TimeoutDigest(round, highQCRound uint64) []byte {
	h := sha256.New()
	h.Write([]byte{domainTimeout})
	writeUint64(h, round)
	writeUint64(h, highQCRound)
	return h.Sum(nil)
}

// qcSigsDigest is what a QC's author signature covers.
func qcSigsDigest(sigs []*diempb.Signature) []byte {
	h := sha256.New()
	h.Write([]byte{domainQCSigs})
	writeSigs(h, sigs)
	return h.Sum(nil)
}

// ExecuteHash is the default speculative execution: a hash chain over the
// previous state and the payload. It is a stand-in for a VM, and it is enough
// for the property DiemBFT actually needs from execution — that honest
// replicas agree on the resulting state id and a diverging one does not.
func ExecuteHash(prev []byte, payload [][]byte) []byte {
	h := sha256.New()
	h.Write([]byte{domainState})
	h.Write(prev)
	writeUint64(h, uint64(len(payload)))
	for _, p := range payload {
		writeBytes(h, p)
	}
	return h.Sum(nil)
}

package hotstuff

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// Domain tags keep a vote signature from ever verifying as a timeout
// signature, or either from verifying as a block hash: each digest starts
// with a distinct byte.
const (
	domainBlock   = 0x01
	domainVote    = 0x02
	domainTimeout = 0x03
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

// blockDigest is the block hash; NewBlock caches it.
//
// The QC is covered by its view and certified hash only, not its signature
// set: two leaders certifying the same block with different quorums must
// still produce the same block hash.
func blockDigest(parent Hash, view View, proposer ID, qc QuorumCert, cmds [][]byte) Hash {
	h := sha256.New()
	h.Write([]byte{domainBlock})
	h.Write(parent[:])
	writeUint64(h, uint64(view))
	writeUint32(h, uint32(proposer))
	writeUint64(h, uint64(len(cmds)))
	for _, c := range cmds {
		writeUint64(h, uint64(len(c)))
		h.Write(c)
	}
	writeUint64(h, uint64(qc.View))
	h.Write(qc.BlockHash[:])
	return Hash(h.Sum(nil))
}

// VoteDigest is what a vote signature covers.
func VoteDigest(view View, blockHash Hash) Hash {
	h := sha256.New()
	h.Write([]byte{domainVote})
	writeUint64(h, uint64(view))
	h.Write(blockHash[:])
	return Hash(h.Sum(nil))
}

// TimeoutDigest is what a timeout signature covers.
func TimeoutDigest(view View) Hash {
	h := sha256.New()
	h.Write([]byte{domainTimeout})
	writeUint64(h, uint64(view))
	return Hash(h.Sum(nil))
}

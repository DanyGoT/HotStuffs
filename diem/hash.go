package diem

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// hashLen is the size of every digest on the wire.
const hashLen = sha256.Size

// domainState follows diempb's domain tags (0x01 to 0x05), so an execution
// state can never pass for a message digest.
const domainState = 0x06

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

func writeUint64(h hash.Hash, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	h.Write(buf[:])
}

func writeBytes(h hash.Hash, b []byte) {
	writeUint64(h, uint64(len(b)))
	h.Write(b)
}

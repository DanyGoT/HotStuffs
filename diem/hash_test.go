package diem

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// TestDomainSeparation checks that the domain tag actually separates the four
// digest functions and the block id: fed correspondingly-shaped zero inputs,
// none of them may collide.
func TestDomainSeparation(t *testing.T) {
	digests := map[string][]byte{
		"VoteInfoHash":       VoteInfoHash(voteInfo(nil, 0, nil, 0)),
		"LedgerCommitDigest": LedgerCommitDigest(commitInfo(nil, voteInfo(nil, 0, nil, 0))),
		"TimeoutDigest":      TimeoutDigest(0, 0),
		"ExecuteHash":        ExecuteHash(zeroHash[:], nil),
		"blockID":            blockID(0, 0, nil, bareQC(nil, 0)),
	}

	seen := make(map[string]string, len(digests))
	for name, d := range digests {
		if other, ok := seen[string(d)]; ok {
			t.Errorf("%s and %s produced the same digest: %x", name, other, d)
			continue
		}
		seen[string(d)] = name
	}
}

func TestVoteInfoFieldSensitivity(t *testing.T) {
	build := func(id byte, round uint64, parent byte, parentRound uint64, exec byte) []byte {
		return VoteInfoHash(diempb.VoteInfo_builder{
			Id:          hashOf(id),
			Round:       round,
			ParentId:    hashOf(parent),
			ParentRound: parentRound,
			ExecStateId: hashOf(exec),
		}.Build())
	}
	base := build(1, 1, 2, 2, 3)

	tests := []struct {
		name string
		got  []byte
	}{
		{"ID", build(9, 1, 2, 2, 3)},
		{"Round", build(1, 9, 2, 2, 3)},
		{"ParentID", build(1, 1, 9, 2, 3)},
		{"ParentRound", build(1, 1, 2, 9, 3)},
		{"ExecStateID", build(1, 1, 2, 2, 9)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bytes.Equal(tt.got, base) {
				t.Errorf("changing %s left VoteInfoHash unchanged", tt.name)
			}
		})
	}
}

func TestLedgerCommitInfoFieldSensitivity(t *testing.T) {
	build := func(state, voteHash byte) []byte {
		return LedgerCommitDigest(diempb.LedgerCommitInfo_builder{
			CommitStateId: hashOf(state),
			VoteInfoHash:  hashOf(voteHash),
		}.Build())
	}
	base := build(1, 2)

	tests := []struct {
		name string
		got  []byte
	}{
		{"CommitStateID", build(9, 2)},
		{"VoteInfoHash", build(1, 9)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bytes.Equal(tt.got, base) {
				t.Errorf("changing %s left LedgerCommitDigest unchanged", tt.name)
			}
		})
	}
}

func TestBlockFieldSensitivity(t *testing.T) {
	baseQC := bareQC(hashOf(7), 0)
	otherQC := bareQC(hashOf(8), 0)
	basePayload := [][]byte{[]byte("payload")}

	base := blockID(1, 1, basePayload, baseQC)

	tests := []struct {
		name string
		id   []byte
	}{
		{"author", blockID(2, 1, basePayload, baseQC)},
		{"round", blockID(1, 2, basePayload, baseQC)},
		{"payload", blockID(1, 1, [][]byte{[]byte("other")}, baseQC)},
		{"qc", blockID(1, 1, basePayload, otherQC)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bytes.Equal(tt.id, base) {
				t.Errorf("changing %s left the block id unchanged", tt.name)
			}
		})
	}
}

// TestBlockIDCoversQCSignatures is the paper's
// hash(author || round || payload || qc.vote_info.id || qc.signatures):
// two otherwise identical blocks over differently-signed QCs must not collide.
func TestBlockIDCoversQCSignatures(t *testing.T) {
	withSig := func(signer uint32, body string) *diempb.QuorumCert {
		return diempb.QuorumCert_builder{
			VoteInfo:   voteInfo(hashOf(1), 0, nil, 0),
			Signatures: []*diempb.Signature{diempb.Signature_builder{Signer: signer, Sig: []byte(body)}.Build()},
		}.Build()
	}

	id1 := blockID(1, 1, [][]byte{[]byte("x")}, withSig(1, "a"))
	id2 := blockID(1, 1, [][]byte{[]byte("x")}, withSig(2, "b"))
	if bytes.Equal(id1, id2) {
		t.Error("blocks differing only in qc.Signatures produced the same id")
	}
}

// TestNewBlockFillsItsID pins that the id a proposer stamps is the digest of
// the block's fields, which is what Verifier.VerifyProposal recomputes.
func TestNewBlockFillsItsID(t *testing.T) {
	qc := bareQC(hashOf(7), 0)
	payload := [][]byte{[]byte("x")}
	b := NewBlock(3, 4, payload, qc)
	if !bytes.Equal(b.GetId(), blockID(3, 4, payload, qc)) {
		t.Error("NewBlock id differs from blockID over the same fields")
	}
}

func TestExecuteHashDeterministic(t *testing.T) {
	prev := hashOf(1)
	payload := [][]byte{[]byte("a"), []byte("b")}
	if !bytes.Equal(ExecuteHash(prev, payload), ExecuteHash(prev, payload)) {
		t.Error("ExecuteHash is not deterministic")
	}
}

func TestExecuteHashOrderSensitive(t *testing.T) {
	prev := hashOf(1)
	h1 := ExecuteHash(prev, [][]byte{[]byte("a"), []byte("b")})
	h2 := ExecuteHash(prev, [][]byte{[]byte("b"), []byte("a")})
	if bytes.Equal(h1, h2) {
		t.Error("ExecuteHash is not sensitive to payload order")
	}
}

// TestDigestsAreStable pins the digest formats byte for byte: replicas that
// disagree on one cannot verify each other's signatures or block ids.
func TestDigestsAreStable(t *testing.T) {
	vi := voteInfo(hashOf(1), 7, hashOf(2), 6)
	vi.SetExecStateId(hashOf(3))
	lc := diempb.LedgerCommitInfo_builder{CommitStateId: hashOf(4), VoteInfoHash: VoteInfoHash(vi)}.Build()
	qcSigs := []*diempb.Signature{
		diempb.Signature_builder{Signer: 1, Sig: []byte("aa")}.Build(),
		diempb.Signature_builder{Signer: 3, Sig: []byte("b")}.Build(),
	}
	qc := diempb.QuorumCert_builder{VoteInfo: vi, Signatures: qcSigs}.Build()

	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{"VoteInfoHash", VoteInfoHash(vi), "8b092d9e1dbfbe317ba4c4fe7a21eab6da1b7500b7cd4e5a50bf145603a0987f"},
		{"LedgerCommitDigest", LedgerCommitDigest(lc), "94b6aaa382393a904b5700b495af6cf451399eaa21cd573d7f1d050e5841d5e9"},
		{"TimeoutDigest", TimeoutDigest(9, 4), "737fd4e1f21f28cb2d2f27cd9485f6bac182d67ef04035c0562e5e7b5e895682"},
		{"qcSigsDigest", qcSigsDigest(qcSigs), "2384fbfc0a4460d7d9ae078019a60bc8ac338b61edf869ec72b7430f6b9bf380"},
		{"blockID", blockID(2, 8, [][]byte{[]byte("x"), nil}, qc), "111d3a701459d73825df094c27e11bc3ec91f7a81f4fc248c5f8d55233573fcb"},
		{"ExecuteHash", ExecuteHash(hashOf(5), [][]byte{[]byte("p")}), "d631f2329d3a9190db1eac55dd53aab5ad9987a4987060c43373c0ed9201131a"},
		{"genesis block id", GenesisBlock().GetId(), "d4b5493ae4acf6cddd60faa01f9719424a318148f4bd46c56cefb26d141bedff"},
	}
	for _, tt := range tests {
		if got := hex.EncodeToString(tt.got); got != tt.want {
			t.Errorf("%s = %s, want %s", tt.name, got, tt.want)
		}
	}
}

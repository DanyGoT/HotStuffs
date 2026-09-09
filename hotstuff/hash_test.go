package hotstuff

import (
	"encoding/hex"
	"testing"
)

func mustHash(t *testing.T, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex fixture %q: %v", s, err)
	}
	var h Hash
	copy(h[:], b)
	return h
}

// Golden vectors: four given by spec, plus independently derived extras (see
// the throwaway Python reimplementation used to compute them, not the Go code
// under test).
func TestGoldenVectors(t *testing.T) {
	tests := []struct {
		name string
		got  Hash
		want string
	}{
		{"genesis", GenesisHash(), "8b3314f6b7a7b5f91246a1f5341b3add0efdee394b6be2e82ecde46887ccf13b"},
		{"vote over genesis", VoteDigest(1, GenesisHash()), "cfd19fc4a4f081168bc37476078f307bb08c1bba8e1fc939a88935103e2f9cb1"},
		{"timeout view 1", TimeoutDigest(1), "3f446a7c4145b1f07aea2e831726d3d3c6a6aac509f40224aca92cc3f0d2805d"},
		{
			"block with two cmds",
			NewBlock(GenesisHash(), 1, 1, QuorumCert{}, [][]byte{[]byte("a"), []byte("bc")}).Hash(),
			"a8a9a87f9a8579ab4d76a342f82124b25e452ef49a8fc3b2d58eee04bd0dbd27",
		},
		{
			"block with non-zero QC, no cmds",
			blockDigest(GenesisHash(), 5, 2, QuorumCert{View: 3, BlockHash: rangeHash()}, nil),
			"08525fbc77c69e876a92de856e0046311ac2c8c2a278a522ce3bff2416160069",
		},
		{
			"block with one empty command",
			blockDigest(GenesisHash(), 1, 1, QuorumCert{}, [][]byte{[]byte("")}),
			"6581d40209899ed7c97dc720becde54a3e0eb8b863f442b5b9da8b31e325606d",
		},
		{
			"block with max view and max proposer",
			blockDigest(GenesisHash(), ^View(0), ^ID(0), QuorumCert{}, [][]byte{[]byte("x")}),
			"6cc5863784555679986a6d526d04923c4784fb269b458f0f248d04ba7db4537b",
		},
	}
	for _, tt := range tests {
		want := mustHash(t, tt.want)
		if tt.got != want {
			t.Errorf("%s: got %x, want %s", tt.name, tt.got, tt.want)
		}
	}
}

// rangeHash is the 32-byte sequence 0x00..0x1f, matching the Python script's
// bytes(range(32)) used to derive the "non-zero QC" golden vector.
func rangeHash() Hash {
	var h Hash
	for i := range h {
		h[i] = byte(i)
	}
	return h
}

// TestBlockDigest_ExcludesQCSignatures documents that the QC's signature set is
// not part of the block hash: two leaders certifying the same block with
// different quorums must not give that block two different hashes.
func TestBlockDigest_ExcludesQCSignatures(t *testing.T) {
	qcHash := rangeHash()
	base := QuorumCert{View: 3, BlockHash: qcHash, Sigs: nil}
	withSigs := QuorumCert{View: 3, BlockHash: qcHash, Sigs: []Signature{
		{Signer: 1, Data: []byte("sig1")},
		{Signer: 2, Data: []byte("sig2")},
	}}
	differentCount := QuorumCert{View: 3, BlockHash: qcHash, Sigs: []Signature{
		{Signer: 7, Data: []byte("solo")},
	}}
	empty := QuorumCert{View: 3, BlockHash: qcHash, Sigs: []Signature{}}

	want := blockDigest(GenesisHash(), 1, 1, base, nil)
	for name, qc := range map[string]QuorumCert{
		"with signatures":       withSigs,
		"different signer set":  differentCount,
		"empty (non-nil) slice": empty,
	} {
		if got := blockDigest(GenesisHash(), 1, 1, qc, nil); got != want {
			t.Errorf("%s: hash changed with QC.Sigs, got %x want %x", name, got, want)
		}
	}
}

// TestBlockDigest_EveryOtherFieldChangesHash varies one field at a time from a
// fixed baseline and checks every resulting digest is pairwise distinct, so no
// two distinct blocks collide by construction.
func TestBlockDigest_EveryOtherFieldChangesHash(t *testing.T) {
	baseParent := Hash{}
	baseView := View(7)
	baseProposer := ID(9)
	baseQCView := View(2)
	baseQCHash := Hash{}
	for i := range baseQCHash {
		baseQCHash[i] = 0xAA
	}
	baseCmds := [][]byte{[]byte("cmd1"), []byte("cmd2")}
	baseQC := QuorumCert{View: baseQCView, BlockHash: baseQCHash}

	altParent := Hash{}
	for i := range altParent {
		altParent[i] = 0x01
	}
	altQCHash := Hash{}
	for i := range altQCHash {
		altQCHash[i] = 0xBB
	}

	digests := map[string]Hash{
		"baseline":     blockDigest(baseParent, baseView, baseProposer, baseQC, baseCmds),
		"alt parent":   blockDigest(altParent, baseView, baseProposer, baseQC, baseCmds),
		"alt view":     blockDigest(baseParent, baseView+1, baseProposer, baseQC, baseCmds),
		"alt proposer": blockDigest(baseParent, baseView, baseProposer+1, baseQC, baseCmds),
		"alt cmds":     blockDigest(baseParent, baseView, baseProposer, baseQC, [][]byte{[]byte("cmd1"), []byte("cmd3")}),
		"alt qc view":  blockDigest(baseParent, baseView, baseProposer, QuorumCert{View: baseQCView + 1, BlockHash: baseQCHash}, baseCmds),
		"alt qc hash":  blockDigest(baseParent, baseView, baseProposer, QuorumCert{View: baseQCView, BlockHash: altQCHash}, baseCmds),
	}

	want := map[string]string{
		"baseline":     "26a0b29b6e783dc687dd6b16bbb100dbeb210d47f133175a2d0423058f13759c",
		"alt parent":   "b05250d2747dbf397bd532baf266eeed068c1a80fd0f25adb31f5890dc58df59",
		"alt view":     "0b09e977cdc062b3bc147bb23044f33300a6a5ca1e436559e925c7f19163c8de",
		"alt proposer": "da2ca843466710915ecb51ddf92b0205819ff8f2d1457e2bf49698a5d9e79c90",
		"alt cmds":     "3f1645e24d74eec36c7683a070d8ed47a6ca21cc4b11cd71832d27fe96dc9088",
		"alt qc view":  "d030b3b94ebf6c013f4d5e6a593997037f988b87bcccacc9c12e3610e8ddc66b",
		"alt qc hash":  "6522e6bcb02285e2a255f3745e20518280e53ed139b0266350f7f0369769e7be",
	}
	for name, w := range want {
		if got := digests[name]; got != mustHash(t, w) {
			t.Errorf("%s: got %x, want %s", name, got, w)
		}
	}

	assertPairwiseDistinct(t, digests)
}

// TestBlockDigest_LengthPrefixDefeatsConcatenation checks that command splits
// which concatenate to the same bytes still hash differently.
func TestBlockDigest_LengthPrefixDefeatsConcatenation(t *testing.T) {
	parent := Hash{}
	view := View(7)
	proposer := ID(9)
	qcHash := Hash{}
	for i := range qcHash {
		qcHash[i] = 0xAA
	}
	qc := QuorumCert{View: 2, BlockHash: qcHash}

	digests := map[string]Hash{
		"ab":     blockDigest(parent, view, proposer, qc, [][]byte{[]byte("ab")}),
		"a,b":    blockDigest(parent, view, proposer, qc, [][]byte{[]byte("a"), []byte("b")}),
		"'',ab":  blockDigest(parent, view, proposer, qc, [][]byte{[]byte(""), []byte("ab")}),
		"ab,''":  blockDigest(parent, view, proposer, qc, [][]byte{[]byte("ab"), []byte("")}),
		"a,'',b": blockDigest(parent, view, proposer, qc, [][]byte{[]byte("a"), []byte(""), []byte("b")}),
	}

	want := map[string]string{
		"ab":     "35a1a73c62263d579f8b03a525e6971fd8b71c1f3b87ac888ba1c37a79f3e8ce",
		"a,b":    "0b6780819c3676406af971656a77a8c7484de6b90495946181bfc0d4e36e2e0d",
		"'',ab":  "6cd13cf436f927229a624c26c48e46329b1cf2a2ca2933f3c728002c13d6866c",
		"ab,''":  "fd09192346542efff4930ccaf3669c589ed56e63626125371a855a1db4caf5f3",
		"a,'',b": "b99b18c4f77625ff94e3b142e40b97f702a40d08263970fd2cbc5321f905a133",
	}
	for name, w := range want {
		if got := digests[name]; got != mustHash(t, w) {
			t.Errorf("%s: got %x, want %s", name, got, w)
		}
	}

	assertPairwiseDistinct(t, digests)
}

// TestDomainSeparation checks that a vote digest, a timeout digest, and a
// block digest never collide for the same view, across several views.
func TestDomainSeparation(t *testing.T) {
	for _, v := range []View{0, 1, 2, 5, ^View(0)} {
		digests := map[string]Hash{
			"vote":    VoteDigest(v, GenesisHash()),
			"timeout": TimeoutDigest(v),
			"block":   blockDigest(GenesisHash(), v, 1, QuorumCert{}, nil),
		}
		assertPairwiseDistinct(t, digests)
	}
}

func assertPairwiseDistinct(t *testing.T, digests map[string]Hash) {
	t.Helper()
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			a, b := names[i], names[j]
			if digests[a] == digests[b] {
				t.Errorf("%q and %q collide: both %x", a, b, digests[a])
			}
		}
	}
}

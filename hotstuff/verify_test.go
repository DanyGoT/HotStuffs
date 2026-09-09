// Package hotstuff_test exercises Verifier from outside hotstuff: it needs
// crypto/nocrypto, which imports hotstuff, so an in-package test would cycle.
package hotstuff_test

import (
	"testing"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/hotstuff"
)

const n = 4

// fixedHash returns a Hash of 32 identical bytes, a distinguishable stand-in
// wherever a test just needs some block hash.
func fixedHash(b byte) hotstuff.Hash {
	var h hotstuff.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// signers returns one nocrypto signer per replica, indexed by ID.
func signers(n int) map[hotstuff.ID]hotstuff.Crypto {
	m := make(map[hotstuff.ID]hotstuff.Crypto, n)
	for i := 1; i <= n; i++ {
		id := hotstuff.ID(i)
		m[id] = nocrypto.New(id, n)
	}
	return m
}

// newVerifier builds a Verifier over n nocrypto replicas and round-robin
// leadership. nocrypto's Verify does not depend on which replica's Signer
// performs it, so any one of them works as the Verifier's crypto.
func newVerifier() *hotstuff.Verifier {
	return hotstuff.NewVerifier(signers(n)[1], hotstuff.RoundRobin(n))
}

// quorumSigs signs msg with replicas 1..count, signer IDs ascending.
func quorumSigs(t *testing.T, msg hotstuff.Hash, count int) []hotstuff.Signature {
	t.Helper()
	s := signers(n)
	sigs := make([]hotstuff.Signature, count)
	for i := range sigs {
		id := hotstuff.ID(i + 1)
		sig, err := s[id].Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		sigs[i] = sig
	}
	return sigs
}

// genesisQC is the one QC every replica accepts at view 0.
func genesisQC() hotstuff.QuorumCert {
	return hotstuff.QuorumCert{View: 0, BlockHash: hotstuff.GenesisHash()}
}

// validQC is a QC over (view, blockHash) signed by a quorum.
func validQC(t *testing.T, view hotstuff.View, h hotstuff.Hash) hotstuff.QuorumCert {
	t.Helper()
	return hotstuff.QuorumCert{View: view, BlockHash: h, Sigs: quorumSigs(t, hotstuff.VoteDigest(view, h), hotstuff.QuorumSize(n))}
}

// validTC is a TC for view signed by a quorum.
func validTC(t *testing.T, view hotstuff.View) *hotstuff.TimeoutCert {
	t.Helper()
	return &hotstuff.TimeoutCert{View: view, Sigs: quorumSigs(t, hotstuff.TimeoutDigest(view), hotstuff.QuorumSize(n))}
}

// buildProposal assembles a proposal without enforcing any relation between
// its fields, so a test can build a deliberately invalid one. signHash
// overrides the hash actually signed; nil means the block's own hash.
func buildProposal(t *testing.T, view hotstuff.View, proposer hotstuff.ID, qc hotstuff.QuorumCert, sigSigner hotstuff.ID, signHash *hotstuff.Hash, tc *hotstuff.TimeoutCert) hotstuff.Proposal {
	t.Helper()
	block := hotstuff.NewBlock(qc.BlockHash, view, proposer, qc, nil)
	h := block.Hash()
	if signHash != nil {
		h = *signHash
	}
	sig, err := nocrypto.New(sigSigner, n).Sign(h)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return hotstuff.Proposal{Block: block, Sig: sig, TC: tc}
}

// validProposal builds a signed proposal for view v carrying qc, proposed and
// signed by RoundRobin(n)(v).
func validProposal(t *testing.T, v hotstuff.View, qc hotstuff.QuorumCert, tc *hotstuff.TimeoutCert) hotstuff.Proposal {
	t.Helper()
	leader := hotstuff.RoundRobin(n)(v)
	return buildProposal(t, v, leader, qc, leader, nil, tc)
}

func TestVerifyQC(t *testing.T) {
	v := newVerifier()
	view := hotstuff.View(5)
	blockHash := fixedHash(0xAB)
	quorum := hotstuff.QuorumSize(n)

	full := quorumSigs(t, hotstuff.VoteDigest(view, blockHash), quorum)

	repeated := append([]hotstuff.Signature{}, full...)
	repeated[1] = repeated[0]

	descending := append([]hotstuff.Signature{}, full...)
	for i, j := 0, len(descending)-1; i < j; i, j = i+1, j-1 {
		descending[i], descending[j] = descending[j], descending[i]
	}

	tests := []struct {
		name string
		qc   hotstuff.QuorumCert
		want bool
	}{
		{"genesis QC", genesisQC(), true},
		{"view 0, non-genesis block hash", hotstuff.QuorumCert{View: 0, BlockHash: fixedHash(1)}, false},
		{
			"view 0, signatures present",
			hotstuff.QuorumCert{View: 0, BlockHash: hotstuff.GenesisHash(), Sigs: quorumSigs(t, hotstuff.VoteDigest(0, hotstuff.GenesisHash()), 1)},
			false,
		},
		{"quorum of valid sigs", hotstuff.QuorumCert{View: view, BlockHash: blockHash, Sigs: full}, true},
		{"quorum-1 sigs", hotstuff.QuorumCert{View: view, BlockHash: blockHash, Sigs: quorumSigs(t, hotstuff.VoteDigest(view, blockHash), quorum-1)}, false},
		// Same signer twice: quorum-1 distinct signers, also caught by the
		// strictly-increasing check before quorum is even counted.
		{"one signer repeated", hotstuff.QuorumCert{View: view, BlockHash: blockHash, Sigs: repeated}, false},
		{"sigs in descending signer order", hotstuff.QuorumCert{View: view, BlockHash: blockHash, Sigs: descending}, false},
		{
			"sigs over a different view's digest",
			hotstuff.QuorumCert{View: view, BlockHash: blockHash, Sigs: quorumSigs(t, hotstuff.VoteDigest(view+1, blockHash), quorum)},
			false,
		},
		{
			"sigs over a different block hash",
			hotstuff.QuorumCert{View: view, BlockHash: blockHash, Sigs: quorumSigs(t, hotstuff.VoteDigest(view, fixedHash(0xCD)), quorum)},
			false,
		},
	}
	for _, tt := range tests {
		if got := v.VerifyQC(tt.qc); got != tt.want {
			t.Errorf("%s: VerifyQC() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestVerifyTC(t *testing.T) {
	v := newVerifier()
	view := hotstuff.View(5)
	blockHash := fixedHash(0xAB)
	quorum := hotstuff.QuorumSize(n)

	full := quorumSigs(t, hotstuff.TimeoutDigest(view), quorum)

	unsorted := append([]hotstuff.Signature{}, full...)
	unsorted[0], unsorted[1] = unsorted[1], unsorted[0]

	duplicated := append([]hotstuff.Signature{}, full...)
	duplicated[1] = duplicated[0]

	tests := []struct {
		name string
		tc   hotstuff.TimeoutCert
		want bool
	}{
		{"view 0", hotstuff.TimeoutCert{View: 0, Sigs: full}, false},
		{"quorum", hotstuff.TimeoutCert{View: view, Sigs: full}, true},
		{"sub-quorum", hotstuff.TimeoutCert{View: view, Sigs: quorumSigs(t, hotstuff.TimeoutDigest(view), quorum-1)}, false},
		{"unsorted signers", hotstuff.TimeoutCert{View: view, Sigs: unsorted}, false},
		{"duplicated signers", hotstuff.TimeoutCert{View: view, Sigs: duplicated}, false},
		{
			// Domain separation: VoteDigest and TimeoutDigest are tagged with
			// different leading bytes, so a vote signature must never verify
			// as a timeout signature for the same view.
			"vote sigs for the same view",
			hotstuff.TimeoutCert{View: view, Sigs: quorumSigs(t, hotstuff.VoteDigest(view, blockHash), quorum)},
			false,
		},
	}
	for _, tt := range tests {
		if got := v.VerifyTC(tt.tc); got != tt.want {
			t.Errorf("%s: VerifyTC() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestVerifyVote(t *testing.T) {
	v := newVerifier()
	view := hotstuff.View(5)
	blockHash := fixedHash(0xAB)

	sign := func(msg hotstuff.Hash, id hotstuff.ID) hotstuff.Signature {
		t.Helper()
		sig, err := nocrypto.New(id, n).Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return sig
	}
	validSig := sign(hotstuff.VoteDigest(view, blockHash), 1)

	tests := []struct {
		name string
		cert hotstuff.PartialCert
		want bool
	}{
		{"valid", hotstuff.PartialCert{View: view, BlockHash: blockHash, Sig: validSig}, true},
		{"view 0", hotstuff.PartialCert{View: 0, BlockHash: blockHash, Sig: sign(hotstuff.VoteDigest(0, blockHash), 1)}, false},
		{"signature over a different view", hotstuff.PartialCert{View: view, BlockHash: blockHash, Sig: sign(hotstuff.VoteDigest(view+1, blockHash), 1)}, false},
		{
			"signature over a different block hash",
			hotstuff.PartialCert{View: view, BlockHash: blockHash, Sig: sign(hotstuff.VoteDigest(view, fixedHash(0xCD)), 1)},
			false,
		},
		{"signer 0", hotstuff.PartialCert{View: view, BlockHash: blockHash, Sig: hotstuff.Signature{Signer: 0, Data: validSig.Data}}, false},
		{"signer n+1", hotstuff.PartialCert{View: view, BlockHash: blockHash, Sig: hotstuff.Signature{Signer: hotstuff.ID(n + 1), Data: validSig.Data}}, false},
		{
			"signature that is actually a timeout signature for the same view",
			hotstuff.PartialCert{View: view, BlockHash: blockHash, Sig: sign(hotstuff.TimeoutDigest(view), 1)},
			false,
		},
	}
	for _, tt := range tests {
		if got := v.VerifyVote(tt.cert); got != tt.want {
			t.Errorf("%s: VerifyVote() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestVerifyTimeout(t *testing.T) {
	v := newVerifier()
	view := hotstuff.View(5)
	blockHash := fixedHash(0xAB)
	quorum := hotstuff.QuorumSize(n)

	sign := func(msg hotstuff.Hash) hotstuff.Signature {
		t.Helper()
		sig, err := nocrypto.New(1, n).Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return sig
	}
	validSig := sign(hotstuff.TimeoutDigest(view))
	quorumQC := validQC(t, view-1, blockHash)

	tests := []struct {
		name string
		m    hotstuff.TimeoutMsg
		want bool
	}{
		{"valid, genesis high QC", hotstuff.TimeoutMsg{View: view, Sig: validSig, HighQC: genesisQC()}, true},
		{"valid, quorum high QC", hotstuff.TimeoutMsg{View: view, Sig: validSig, HighQC: quorumQC}, true},
		{"view 0", hotstuff.TimeoutMsg{View: 0, Sig: sign(hotstuff.TimeoutDigest(0)), HighQC: genesisQC()}, false},
		{
			"invalid high QC, sub-quorum",
			hotstuff.TimeoutMsg{
				View: view,
				Sig:  validSig,
				HighQC: hotstuff.QuorumCert{
					View: view - 1, BlockHash: blockHash,
					Sigs: quorumSigs(t, hotstuff.VoteDigest(view-1, blockHash), quorum-1),
				},
			},
			false,
		},
		{
			"forged genesis high QC",
			hotstuff.TimeoutMsg{View: view, Sig: validSig, HighQC: hotstuff.QuorumCert{View: 0, BlockHash: fixedHash(1)}},
			false,
		},
		{"signature over a different view", hotstuff.TimeoutMsg{View: view, Sig: sign(hotstuff.TimeoutDigest(view + 1)), HighQC: genesisQC()}, false},
		{
			"signature that is actually a vote signature",
			hotstuff.TimeoutMsg{View: view, Sig: sign(hotstuff.VoteDigest(view, blockHash)), HighQC: genesisQC()},
			false,
		},
	}
	for _, tt := range tests {
		if got := v.VerifyTimeout(tt.m); got != tt.want {
			t.Errorf("%s: VerifyTimeout() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestVerifyProposal(t *testing.T) {
	v := newVerifier()
	quorum := hotstuff.QuorumSize(n)

	// view 1's leader is RoundRobin(n)(1) = 2; the happy path needs no TC
	// since the genesis QC already sits at view 0 = 1-1.
	leader1 := hotstuff.RoundRobin(n)(1)
	// view 5's leader is RoundRobin(n)(5) = 2, same replica, distinct view.
	leader5 := hotstuff.RoundRobin(n)(5)

	qcHash3 := fixedHash(0x33)
	qcView3 := validQC(t, 3, qcHash3) // certifies view 3: a gap before view 5

	tests := []struct {
		name string
		p    hotstuff.Proposal
		want bool
	}{
		{"valid", validProposal(t, 1, genesisQC(), nil), true},
		{"nil block", hotstuff.Proposal{Block: nil}, false},
		{"block at view 0", hotstuff.Proposal{Block: hotstuff.NewBlock(hotstuff.GenesisHash(), 0, 1, hotstuff.QuorumCert{}, nil)}, false},
		{
			"proposer is not the view's leader",
			buildProposal(t, 1, leader1+1, genesisQC(), leader1+1, nil, nil),
			false,
		},
		{
			"sig.Signer does not match the block's proposer",
			buildProposal(t, 1, leader1, genesisQC(), leader1+1, nil, nil),
			false,
		},
		{
			"QC.View equal to the block's view",
			buildProposal(t, 5, leader5, hotstuff.QuorumCert{View: 5, BlockHash: fixedHash(0xAB)}, leader5, nil, nil),
			false,
		},
		{
			"QC.View greater than the block's view",
			buildProposal(t, 5, leader5, hotstuff.QuorumCert{View: 6, BlockHash: fixedHash(0xAB)}, leader5, nil, nil),
			false,
		},
		{
			"QC invalid, sub-quorum",
			buildProposal(t, 5, leader5, hotstuff.QuorumCert{
				View: 4, BlockHash: fixedHash(0xAB),
				Sigs: quorumSigs(t, hotstuff.VoteDigest(4, fixedHash(0xAB)), quorum-1),
			}, leader5, nil, nil),
			false,
		},
		{
			"QC is a forged genesis QC",
			buildProposal(t, 1, leader1, hotstuff.QuorumCert{View: 0, BlockHash: fixedHash(1)}, leader1, nil, nil),
			false,
		},
		{
			"view gap with no TC",
			buildProposal(t, 5, leader5, qcView3, leader5, nil, nil),
			false,
		},
		{
			"view gap justified by a valid TC",
			buildProposal(t, 5, leader5, qcView3, leader5, nil, validTC(t, 4)),
			true,
		},
		{
			"TC present but for the wrong view",
			buildProposal(t, 5, leader5, qcView3, leader5, nil, validTC(t, 3)),
			false,
		},
		{
			"TC present but sub-quorum",
			buildProposal(t, 5, leader5, qcView3, leader5, nil, &hotstuff.TimeoutCert{
				View: 4, Sigs: quorumSigs(t, hotstuff.TimeoutDigest(4), quorum-1),
			}),
			false,
		},
		{
			"proposal signature over some other hash",
			buildProposal(t, 1, leader1, genesisQC(), leader1, func() *hotstuff.Hash { h := fixedHash(0x77); return &h }(), nil),
			false,
		},
	}
	for _, tt := range tests {
		if got := v.VerifyProposal(tt.p); got != tt.want {
			t.Errorf("%s: VerifyProposal() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestQuorumReached(t *testing.T) {
	// verify treats any non-nil Data as a valid signature; QuorumReached's own
	// counting logic, not the crypto, is what these tables exercise.
	valid := func(id hotstuff.ID) hotstuff.Signature { return hotstuff.Signature{Signer: id, Data: []byte{1}} }
	invalid := func(id hotstuff.ID) hotstuff.Signature { return hotstuff.Signature{Signer: id, Data: nil} }
	verify := func(_ hotstuff.Hash, sig hotstuff.Signature) bool { return sig.Data != nil }
	msg := fixedHash(0)

	sigsOf := func(f func(hotstuff.ID) hotstuff.Signature, from, to int) []hotstuff.Signature {
		var sigs []hotstuff.Signature
		for i := from; i <= to; i++ {
			sigs = append(sigs, f(hotstuff.ID(i)))
		}
		return sigs
	}

	for _, n := range []int{4, 7} {
		quorum := hotstuff.QuorumSize(n)
		tests := []struct {
			name string
			sigs []hotstuff.Signature
			want bool
		}{
			{"exactly quorum distinct valid", sigsOf(valid, 1, quorum), true},
			{"quorum-1 distinct valid", sigsOf(valid, 1, quorum-1), false},
			{"quorum valid plus some invalid", append(sigsOf(valid, 1, quorum), sigsOf(invalid, quorum+1, quorum+2)...), true},
			{"duplicate signer counted once", append(sigsOf(valid, 1, quorum-1), valid(1)), false},
			{"empty", nil, false},
		}
		for _, tt := range tests {
			if got := hotstuff.QuorumReached(n, msg, tt.sigs, verify); got != tt.want {
				t.Errorf("n=%d %s: QuorumReached() = %v, want %v", n, tt.name, got, tt.want)
			}
		}
	}

	// n = 1 has quorum 1 too, but zero signatures still cannot reach it.
	if hotstuff.QuorumReached(1, msg, nil, verify) {
		t.Error("QuorumReached(1, ..., nil, ...) = true, want false")
	}
}

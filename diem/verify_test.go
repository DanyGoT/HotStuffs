package diem

import (
	"slices"
	"testing"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
)

// The tests here cover the boundary the paper delegates to "other parts of the
// system": everything that is dropped before a message reaches the consensus
// goroutine. A Byzantine replica's whole surface is what it can put on the
// wire, so a message that fails any of these checks must leave no trace.

// newTestVerifier returns the Verifier for the 4-replica group testN and
// testQuorum describe.
func newTestVerifier() *Verifier {
	return NewVerifier(nocrypto.New(1, testN), testQuorum)
}

// TestVerifyRejectsNonCanonicalCertificates pins the canonical signer order on
// inbound certificates. A block id covers its parent certificate's signature
// slice byte for byte (blockID), so a leader that permutes or pads one valid
// quorum mints arbitrarily many distinct, individually valid blocks over the
// same parent — one entry in the pending tree and one speculated state each.
// Deduplication inside VerifyQuorum does not catch it: it counts signers and
// says nothing about their order or the slice's length.
func TestVerifyRejectsNonCanonicalCertificates(t *testing.T) {
	v := newTestVerifier()
	voteInfo := VoteInfo{ID: GenesisBlock().ID(), Round: 1}

	t.Run("QC signatures out of signer order", func(t *testing.T) {
		qc := makeQC(voteInfo, Hash{}, 1, 2, 3)
		if !v.VerifyQC(qc) {
			t.Fatal("VerifyQC = false for a canonical quorum, want true")
		}
		slices.Reverse(qc.Signatures)
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a permuted signature set, want false")
		}
	})

	t.Run("QC signatures padded with a repeated signer", func(t *testing.T) {
		qc := makeQC(voteInfo, Hash{}, 1, 2, 3)
		qc.Signatures = append(qc.Signatures, qc.Signatures[0])
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a padded signature set, want false")
		}
	})

	t.Run("TC votes out of signer order", func(t *testing.T) {
		tc := makeTC(5, 3, 4, 5)
		if !v.VerifyTC(tc) {
			t.Fatal("VerifyTC = false for a canonical quorum, want true")
		}
		slices.Reverse(tc.Votes)
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true for a permuted vote set, want false")
		}
	})
}

// TestVerifyProposalRejectsCertificateAtOrAboveItsOwnRound pins the bound the
// well-formedness rule leaves open on its TC branch: a proposal for round r
// behind a TC for r-1 may carry any QC at all, including one at or above r.
// safeToVote does refuse to vote for it, but only after processCertificateQC
// has dragged the pacemaker to the certificate's round and ExecuteAndInsert has
// speculated and stored the block.
func TestVerifyProposalRejectsCertificateAtOrAboveItsOwnRound(t *testing.T) {
	v := newTestVerifier()
	qc := makeQC(VoteInfo{ID: Hash{0x11}, Round: 10}, Hash{}, 1, 2, 3)
	b := NewBlock(1, 5, [][]byte{{0xaa}}, qc)
	p := &ProposalMsg{
		Block:       b,
		LastRoundTC: makeTC(4, 1, 2, 3),
		Sender:      1,
		Sig:         signAs(1, b.ID()),
	}
	if !p.WellFormed() {
		t.Fatal("setup: the proposal is meant to pass the well-formedness rule")
	}
	if v.VerifyProposal(p) {
		t.Error("VerifyProposal = true for a block whose QC is at round 10 and its own round 5, want false")
	}
}

// TestVerifyTCRejectsRoundZero covers a guard, not a fix: safeToTimeout
// refuses round 0, so a quorum of round-0 timeouts is unreachable from honest
// replicas and no bug was ever exploitable here. The check is free and it keeps
// this verifier and package hotstuff's symmetric.
func TestVerifyTCRejectsRoundZero(t *testing.T) {
	if newTestVerifier().VerifyTC(makeTC(0, 1, 2, 3)) {
		t.Error("VerifyTC = true for a TC claiming round 0, want false")
	}
}

func TestVerifyQC(t *testing.T) {
	v := newTestVerifier()

	t.Run("nil is invalid", func(t *testing.T) {
		if v.VerifyQC(nil) {
			t.Error("VerifyQC(nil) = true, want false")
		}
	})

	t.Run("genesis qc is valid", func(t *testing.T) {
		if !v.VerifyQC(GenesisQC()) {
			t.Error("VerifyQC(GenesisQC()) = false, want true")
		}
	})

	t.Run("vote info not bound to the ledger commit info is rejected", func(t *testing.T) {
		voteInfo := VoteInfo{ID: GenesisBlock().ID(), Round: 1}
		qc := makeQC(voteInfo, Hash{}, 1, 2, 3)
		qc.VoteInfo.Round = 2 // tamper after the commit hash was computed over Round: 1
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a QC whose VoteInfo does not match its LedgerCommitInfo hash")
		}
	})

	t.Run("too few signatures is rejected", func(t *testing.T) {
		voteInfo := VoteInfo{ID: GenesisBlock().ID(), Round: 1}
		qc := makeQC(voteInfo, Hash{}, 1, 2) // quorum is 3
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true below quorum, want false")
		}
	})
}

func TestVerifyTC(t *testing.T) {
	v := newTestVerifier()

	t.Run("nil is valid", func(t *testing.T) {
		if !v.VerifyTC(nil) {
			t.Error("VerifyTC(nil) = false, want true")
		}
	})

	t.Run("duplicate signers rejected", func(t *testing.T) {
		tc := &TC{Round: 5, Votes: []TimeoutVote{
			{HighQCRound: 3, Sig: signAs(1, TimeoutDigest(5, 3))},
			{HighQCRound: 3, Sig: signAs(1, TimeoutDigest(5, 3))},
			{HighQCRound: 4, Sig: signAs(2, TimeoutDigest(5, 4))},
		}}
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true with a duplicate signer, want false")
		}
	})

	t.Run("wrong-digest signature rejected", func(t *testing.T) {
		tc := &TC{Round: 5, Votes: []TimeoutVote{
			{HighQCRound: 3, Sig: signAs(1, TimeoutDigest(5, 3))},
			{HighQCRound: 4, Sig: signAs(2, TimeoutDigest(99, 4))}, // signed a different round
			{HighQCRound: 5, Sig: signAs(3, TimeoutDigest(5, 5))},
		}}
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true with a signature over the wrong digest, want false")
		}
	})

	t.Run("below quorum rejected", func(t *testing.T) {
		tc := makeTC(5, 3, 4) // 2 signers, quorum is 3
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true below quorum, want false")
		}
	})

	t.Run("quorum of distinct signers accepted", func(t *testing.T) {
		tc := makeTC(5, 3, 4, 5)
		if !v.VerifyTC(tc) {
			t.Error("VerifyTC = false for a valid quorum, want true")
		}
	})
}

// TestVerifyProposalRejects is the envelope half of the proposal checks: what a
// receiver can judge from the message and the replica set alone. Whether the
// author leads the round is Core's, and diem/core_test.go holds that case.
func TestVerifyProposalRejects(t *testing.T) {
	v := newTestVerifier()
	tests := []struct {
		name string
		msg  func() *ProposalMsg
	}{
		{"signature is by someone other than the sender", func() *ProposalMsg {
			p := proposal(1, 1, 1)
			p.Sig = signAs(3, p.Block.ID())
			return p
		}},
		{"signature covers something other than the block", func() *ProposalMsg {
			p := proposal(1, 1, 1)
			p.Sig = signAs(1, Hash{0xff})
			return p
		}},
		{"carries a TC its own QC already makes redundant", func() *ProposalMsg {
			// Well-formedness: a proposal for round r carries the TC of r-1
			// only when its QC is not from r-1. Genesis is from round 0, so
			// any TC here is redundant and the proposal is ill-formed.
			p := proposal(1, 1, 1)
			p.LastRoundTC = &TC{Round: 0}
			return p
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v.VerifyProposal(tt.msg()) {
				t.Error("VerifyProposal = true for a proposal that should have been dropped")
			}
		})
	}
}

// TestVerifyRejectsForgedCertificate pins the check on the certificates a
// message carries, rather than on the message envelope. An unsigned QC that
// claims a high round is the cheapest attack there is: accepting it would drag
// the replica's round and its highest certificate forward on no evidence, and
// no later leader or round check would notice.
func TestVerifyRejectsForgedCertificate(t *testing.T) {
	v := newTestVerifier()
	forged := &QC{VoteInfo: VoteInfo{ID: Hash{0x99}, Round: 40}}

	t.Run("on a proposal", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.HighCommitQC = forged
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a proposal carrying a forged commit certificate")
		}
	})
	t.Run("as a block's parent certificate", func(t *testing.T) {
		b := NewBlock(1, 41, [][]byte{{0xaa}}, forged)
		p := &ProposalMsg{Block: b, HighCommitQC: genesisQC, Sender: 1, Sig: signAs(1, b.ID())}
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block extending a forged certificate")
		}
	})
	t.Run("on a timeout", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.HighCommitQC = forged
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true for a timeout carrying a forged commit certificate")
		}
	})
	t.Run("on a vote", func(t *testing.T) {
		p := proposal(1, 1, 1)
		vote := voteFor(t, 1, p.Block)
		vote.HighCommitQC = forged
		if v.VerifyVote(vote) {
			t.Error("VerifyVote = true for a vote carrying a forged commit certificate")
		}
	})
}

// TestVerifyQCRejectsUnattributedAuthor pins the author signature (3.3,
// process_vote: author <- u, author_signature <- sign_u(signatures)). It
// certifies nothing the quorum does not, so a replica could ignore it and stay
// safe; what it buys is attribution. A QC's signature set is chosen by whoever
// assembled it, and a block id covers that set, so an aggregator that hands out
// two different quorums over one vote is the one thing the quorum signatures
// alone cannot pin on anybody. Unchecked, the field is decoration a Byzantine
// aggregator fills in with any name it likes.
func TestVerifyQCRejectsUnattributedAuthor(t *testing.T) {
	v := newTestVerifier()
	voteInfo := VoteInfo{ID: GenesisBlock().ID(), Round: 1}

	if !v.VerifyQC(makeQC(voteInfo, Hash{}, 1, 2, 3)) {
		t.Fatal("VerifyQC = false for a quorum its author signed, want true")
	}
	if !v.VerifyQC(GenesisQC()) {
		t.Fatal("VerifyQC = false for genesis, want true: it is trusted, not certified")
	}

	tamper := map[string]func(*QC){
		"no author signature at all": func(qc *QC) {
			qc.AuthorSig = Signature{}
		},
		"author signature by someone other than the named author": func(qc *QC) {
			qc.Author = 2
		},
		"author signature covers a different signature set": func(qc *QC) {
			qc.AuthorSig = signAs(qc.Author, qcSigsDigest(makeQC(voteInfo, Hash{}, 2, 3, 4).Signatures))
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			qc := makeQC(voteInfo, Hash{}, 1, 2, 3)
			break_(qc)
			if v.VerifyQC(qc) {
				t.Error("VerifyQC = true for a certificate no author is bound to")
			}
		})
	}
}

func TestVerifyVoteRejects(t *testing.T) {
	v := newTestVerifier()
	tamper := map[string]func(*VoteMsg){
		"VoteInfo does not match the hash the signature binds": func(m *VoteMsg) {
			m.VoteInfo.Round = 9
		},
		"signature is by someone other than the sender": func(m *VoteMsg) {
			m.Sender = 4
		},
		"signature covers something other than the ledger commit info": func(m *VoteMsg) {
			m.Sig = signAs(m.Sender, Hash{0xff})
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			m := voteFor(t, 1, proposal(1, 1, 1).Block)
			break_(m)
			if v.VerifyVote(m) {
				t.Error("VerifyVote = true for a vote that should have been dropped")
			}
		})
	}
}

func TestVerifyTimeoutRejects(t *testing.T) {
	v := newTestVerifier()
	tamper := map[string]func(*TimeoutMsg){
		"signature is by someone other than the sender": func(m *TimeoutMsg) {
			m.TmoInfo.Sender = 4
		},
		"signature covers a different round": func(m *TimeoutMsg) {
			m.TmoInfo.Sig = signAs(m.TmoInfo.Sender, TimeoutDigest(9, 0))
		},
		"high QC is forged": func(m *TimeoutMsg) {
			m.TmoInfo.HighQC = &QC{VoteInfo: VoteInfo{ID: Hash{0x99}, Round: 5}}
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			m := timeoutFrom(t, 1)
			break_(m)
			if v.VerifyTimeout(m) {
				t.Error("VerifyTimeout = true for a timeout that should have been dropped")
			}
		})
	}
}

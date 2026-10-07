package diem

import (
	"slices"
	"testing"

	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"google.golang.org/protobuf/proto"
)

// The tests here cover the boundary the paper delegates to "other parts of the
// system": everything that is dropped before a message reaches the consensus
// goroutine. A Byzantine replica's whole surface is what it can put on the
// wire, so a message that fails any of these checks must leave no trace.

// newTestVerifier returns the Verifier for the 4-replica group testN and
// testQuorum describe.
func newTestVerifier() *Verifier {
	return NewVerifier(newTestSigner(testN), testQuorum)
}

// TestVerifyRejectsNonCanonicalCertificates pins the canonical signer order on
// inbound certificates. A block id covers its parent certificate's signature
// slice byte for byte (blockID), so a leader that permutes or pads one valid
// quorum mints arbitrarily many distinct, individually valid blocks over the
// same parent — one entry in the pending tree and one speculated state each.
// Deduplication inside QuorumReached does not catch it: it counts signers and
// says nothing about their order or the slice's length.
func TestVerifyRejectsNonCanonicalCertificates(t *testing.T) {
	v := newTestVerifier()
	vi := voteInfo(GenesisBlock().GetId(), 1, nil, 0)

	t.Run("QC signatures out of signer order", func(t *testing.T) {
		qc := makeQC(vi, nil, 1, 2, 3)
		if !v.VerifyQC(qc) {
			t.Fatal("VerifyQC = false for a canonical quorum, want true")
		}
		slices.Reverse(qc.GetSignatures())
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a permuted signature set, want false")
		}
	})

	t.Run("QC signatures padded with a repeated signer", func(t *testing.T) {
		qc := makeQC(vi, nil, 1, 2, 3)
		qc.SetSignatures(append(qc.GetSignatures(), qc.GetSignatures()[0]))
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a padded signature set, want false")
		}
	})

	t.Run("TC votes out of signer order", func(t *testing.T) {
		tc := makeTC(5, 3, 4, 5)
		if !v.VerifyTC(tc) {
			t.Fatal("VerifyTC = false for a canonical quorum, want true")
		}
		slices.Reverse(tc.GetVotes())
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
	qc := makeQC(voteInfo(hashOf(0x11), 10, nil, 0), nil, 1, 2, 3)
	b := NewBlock(1, 5, [][]byte{{0xaa}}, qc)
	p := diempb.ProposalMsg_builder{
		Block:       b,
		LastRoundTc: makeTC(4, 1, 2, 3),
		Sender:      1,
		Sig:         signAs(1, b.GetId()),
	}.Build()
	if !WellFormedProposal(p) {
		t.Fatal("setup: the proposal is meant to pass the well-formedness rule")
	}
	if v.VerifyProposal(p) {
		t.Error("VerifyProposal = true for a block whose QC is at round 10 and its own round 5, want false")
	}
}

// TestVerifyTCRejectsRoundZero covers a guard, not a fix: safeToTimeout
// refuses round 0, so a quorum of round-0 timeouts is unreachable from honest
// replicas and no bug was ever exploitable here. The check is free.
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
		vi := voteInfo(GenesisBlock().GetId(), 1, nil, 0)
		qc := makeQC(vi, nil, 1, 2, 3)
		qc.GetVoteInfo().SetRound(2) // tamper after the commit hash was computed over Round: 1
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a QC whose VoteInfo does not match its LedgerCommitInfo hash")
		}
	})

	t.Run("commit over a round gap is rejected", func(t *testing.T) {
		vi := voteInfo(hashOf(2), 3, GenesisBlock().GetId(), 1)
		if v.VerifyQC(makeQC(vi, hashOf(9), 1, 2, 3)) {
			t.Error("VerifyQC = true for a commit whose block does not directly follow its parent")
		}
		vi = voteInfo(hashOf(2), 2, GenesisBlock().GetId(), 1)
		if !v.VerifyQC(makeQC(vi, hashOf(9), 1, 2, 3)) {
			t.Error("VerifyQC = false for a 2-chain commit, want true")
		}
	})

	t.Run("too few signatures is rejected", func(t *testing.T) {
		vi := voteInfo(GenesisBlock().GetId(), 1, nil, 0)
		qc := makeQC(vi, nil, 1, 2) // quorum is 3
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
		tc := tcOf(5,
			tcVote(3, signAs(1, TimeoutDigest(5, 3))),
			tcVote(3, signAs(1, TimeoutDigest(5, 3))),
			tcVote(4, signAs(2, TimeoutDigest(5, 4))))
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true with a duplicate signer, want false")
		}
	})

	t.Run("wrong-digest signature rejected", func(t *testing.T) {
		tc := tcOf(5,
			tcVote(3, signAs(1, TimeoutDigest(5, 3))),
			tcVote(4, signAs(2, TimeoutDigest(99, 4))), // signed a different round
			tcVote(5, signAs(3, TimeoutDigest(5, 5))))
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
		msg  func() *diempb.ProposalMsg
	}{
		{"signature is by someone other than the sender", func() *diempb.ProposalMsg {
			p := proposal(1, 1, 1)
			p.SetSig(signAs(3, p.GetBlock().GetId()))
			return p
		}},
		{"signature covers something other than the block", func() *diempb.ProposalMsg {
			p := proposal(1, 1, 1)
			p.SetSig(signAs(1, hashOf(0xff)))
			return p
		}},
		{"carries a TC its own QC already makes redundant", func() *diempb.ProposalMsg {
			// Well-formedness: a proposal for round r carries the TC of r-1
			// only when its QC is not from r-1. Genesis is from round 0, so
			// any TC here is redundant and the proposal is ill-formed.
			p := proposal(1, 1, 1)
			p.SetLastRoundTc(makeTC(0))
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
	forged := bareQC(hashOf(0x99), 40)

	t.Run("on a proposal", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.SetHighCommitQc(forged)
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a proposal carrying a forged commit certificate")
		}
	})
	t.Run("as a block's parent certificate", func(t *testing.T) {
		b := NewBlock(1, 41, [][]byte{{0xaa}}, forged)
		p := diempb.ProposalMsg_builder{Block: b, HighCommitQc: genesisQC, Sender: 1, Sig: signAs(1, b.GetId())}.Build()
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block extending a forged certificate")
		}
	})
	t.Run("on a timeout", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.SetHighCommitQc(forged)
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true for a timeout carrying a forged commit certificate")
		}
	})
	t.Run("on a vote", func(t *testing.T) {
		p := proposal(1, 1, 1)
		vote := voteFor(t, 1, p.GetBlock())
		vote.SetHighCommitQc(forged)
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
	vi := voteInfo(GenesisBlock().GetId(), 1, nil, 0)

	if !v.VerifyQC(makeQC(vi, nil, 1, 2, 3)) {
		t.Fatal("VerifyQC = false for a quorum its author signed, want true")
	}
	if !v.VerifyQC(GenesisQC()) {
		t.Fatal("VerifyQC = false for genesis, want true: it is trusted, not certified")
	}

	tamper := map[string]func(*diempb.QuorumCert){
		"no author signature at all": func(qc *diempb.QuorumCert) {
			qc.ClearAuthorSig()
		},
		"author signature by someone other than the named author": func(qc *diempb.QuorumCert) {
			qc.SetAuthor(2)
		},
		"author signature covers a different signature set": func(qc *diempb.QuorumCert) {
			qc.SetAuthorSig(signAs(qc.GetAuthor(), qcSigsDigest(makeQC(vi, nil, 2, 3, 4).GetSignatures())))
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			qc := makeQC(vi, nil, 1, 2, 3)
			break_(qc)
			if v.VerifyQC(qc) {
				t.Error("VerifyQC = true for a certificate no author is bound to")
			}
		})
	}
}

func TestVerifyVoteRejects(t *testing.T) {
	v := newTestVerifier()
	tamper := map[string]func(*diempb.VoteMsg){
		"VoteInfo does not match the hash the signature binds": func(m *diempb.VoteMsg) {
			m.GetVoteInfo().SetRound(9)
		},
		"signature is by someone other than the sender": func(m *diempb.VoteMsg) {
			m.SetSender(4)
		},
		"signature covers something other than the ledger commit info": func(m *diempb.VoteMsg) {
			m.SetSig(signAs(m.GetSender(), hashOf(0xff)))
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			m := voteFor(t, 1, proposal(1, 1, 1).GetBlock())
			break_(m)
			if v.VerifyVote(m) {
				t.Error("VerifyVote = true for a vote that should have been dropped")
			}
		})
	}
}

func TestVerifyTimeoutRejects(t *testing.T) {
	v := newTestVerifier()
	tamper := map[string]func(*diempb.TimeoutMsg){
		"signature is by someone other than the sender": func(m *diempb.TimeoutMsg) {
			m.GetTmoInfo().SetSender(4)
		},
		"signature covers a different round": func(m *diempb.TimeoutMsg) {
			m.GetTmoInfo().SetSig(signAs(m.GetTmoInfo().GetSender(), TimeoutDigest(9, 0)))
		},
		"high QC is forged": func(m *diempb.TimeoutMsg) {
			m.GetTmoInfo().SetHighQc(bareQC(hashOf(0x99), 5))
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

func tcVote(highQCRound uint64, sig *diempb.Signature) *diempb.TimeoutVote {
	return diempb.TimeoutVote_builder{HighQcRound: highQCRound, Sig: sig}.Build()
}

func tcOf(round uint64, votes ...*diempb.TimeoutVote) *diempb.TimeoutCert {
	return diempb.TimeoutCert_builder{Round: round, Votes: votes}.Build()
}

// TestVerifyRejectsMalformed covers what arrives from a peer that builds its
// messages by hand: absent parts, hashes of the wrong length, a block id that
// is not the digest of its fields. Every hash field of a message the Verifier
// accepts is exactly hashLen bytes, which is what lets the core read them
// without checking.
func TestVerifyRejectsMalformed(t *testing.T) {
	v := newTestVerifier()
	short := []byte{1, 2, 3}

	// A vote whose own fields are broken, re-signed so that only the field
	// under test is wrong.
	reVote := func(vi *diempb.VoteInfo, commit *diempb.LedgerCommitInfo) *diempb.VoteMsg {
		return diempb.VoteMsg_builder{
			VoteInfo: vi, LedgerCommitInfo: commit, Sender: 1,
			Sig: signAs(1, LedgerCommitDigest(commit)),
		}.Build()
	}
	good := voteInfo(hashOf(1), 1, GenesisBlock().GetId(), 0)
	withInfo := func(mut func(*diempb.VoteInfo)) *diempb.VoteMsg {
		vi := proto.Clone(good).(*diempb.VoteInfo)
		mut(vi)
		return reVote(vi, commitInfo(nil, vi))
	}
	withCommit := func(mut func(*diempb.LedgerCommitInfo)) *diempb.VoteMsg {
		c := commitInfo(nil, good)
		mut(c)
		return reVote(good, c)
	}
	if !v.VerifyVote(reVote(good, commitInfo(nil, good))) {
		t.Fatal("setup: the control vote must verify")
	}

	votes := map[string]*diempb.VoteMsg{
		"nil vote":                   nil,
		"vote without vote info":     reVote(nil, commitInfo(nil, good)),
		"vote without commit info":   reVote(good, nil),
		"vote without a signature":   diempb.VoteMsg_builder{VoteInfo: good, LedgerCommitInfo: commitInfo(nil, good), Sender: 1}.Build(),
		"vote sender 0":              diempb.VoteMsg_builder{VoteInfo: good, LedgerCommitInfo: commitInfo(nil, good), Sig: signAs(0, hashOf())}.Build(),
		"short vote info id":         withInfo(func(vi *diempb.VoteInfo) { vi.SetId(short) }),
		"short vote info parent id":  withInfo(func(vi *diempb.VoteInfo) { vi.SetParentId(short) }),
		"short vote info exec state": withInfo(func(vi *diempb.VoteInfo) { vi.SetExecStateId(short) }),
		"short commit state id":      withCommit(func(c *diempb.LedgerCommitInfo) { c.SetCommitStateId(short) }),
		"short vote info hash":       withCommit(func(c *diempb.LedgerCommitInfo) { c.SetVoteInfoHash(short) }),
		"long commit state id":       withCommit(func(c *diempb.LedgerCommitInfo) { c.SetCommitStateId(append(hashOf(), 0)) }),
	}
	for name, m := range votes {
		t.Run(name, func(t *testing.T) {
			if v.VerifyVote(m) {
				t.Error("VerifyVote = true for a malformed vote")
			}
		})
	}

	t.Run("nil quorum cert", func(t *testing.T) {
		if v.VerifyQC(nil) {
			t.Error("VerifyQC(nil) = true")
		}
	})
	t.Run("quorum cert without vote or commit info", func(t *testing.T) {
		if v.VerifyQC(diempb.QuorumCert_builder{}.Build()) {
			t.Error("VerifyQC = true for an empty certificate")
		}
	})
	t.Run("genesis certificate with a short hash", func(t *testing.T) {
		qc := proto.Clone(GenesisQC()).(*diempb.QuorumCert)
		qc.GetVoteInfo().SetParentId(short)
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for genesis with a short parent id")
		}
	})
	t.Run("quorum cert with a short hash", func(t *testing.T) {
		qc := makeQC(voteInfo(GenesisBlock().GetId(), 1, nil, 0), nil, 1, 2, 3)
		qc.GetVoteInfo().SetExecStateId(short)
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a certificate with a short exec state id")
		}
	})
	t.Run("quorum cert with a nil signature", func(t *testing.T) {
		qc := makeQC(voteInfo(GenesisBlock().GetId(), 1, nil, 0), nil, 1, 2, 3)
		qc.SetSignatures(append(qc.GetSignatures()[:2:2], nil))
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true with a nil signature in the set")
		}
	})
	t.Run("timeout cert with a nil vote", func(t *testing.T) {
		if v.VerifyTC(tcOf(5, nil, nil, nil)) {
			t.Error("VerifyTC = true for nil votes")
		}
	})

	t.Run("nil proposal", func(t *testing.T) {
		if v.VerifyProposal(nil) {
			t.Error("VerifyProposal(nil) = true")
		}
	})
	t.Run("proposal without a block", func(t *testing.T) {
		if v.VerifyProposal(diempb.ProposalMsg_builder{Sender: 1, Sig: signAs(1, hashOf())}.Build()) {
			t.Error("VerifyProposal = true without a block")
		}
	})
	t.Run("block without a qc", func(t *testing.T) {
		b := diempb.Block_builder{Author: 1, Round: 1}.Build()
		b.SetId(blockID(1, 1, nil, nil))
		p := diempb.ProposalMsg_builder{Block: b, Sender: 1, Sig: signAs(1, b.GetId())}.Build()
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block without a qc")
		}
	})
	t.Run("proposal without a signature", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.ClearSig()
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true without a signature")
		}
	})
	t.Run("proposal sender 0", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.SetSender(0)
		p.SetSig(signAs(0, p.GetBlock().GetId()))
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for sender 0")
		}
	})
	t.Run("proposal with a malformed commit qc", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.SetHighCommitQc(diempb.QuorumCert_builder{}.Build())
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true with an empty commit certificate")
		}
	})

	// The id is a claim like every other digest on the wire: a proposal
	// carrying a different one, correctly signed, must still be dropped.
	t.Run("block id that is not the digest of its fields", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.GetBlock().SetId(hashOf(0xee))
		p.SetSig(signAs(1, p.GetBlock().GetId()))
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block whose id is not recomputed from its fields")
		}
	})
	t.Run("block without an id", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.GetBlock().SetId(nil)
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block with no id")
		}
	})
	t.Run("block id over a tampered payload", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.GetBlock().SetPayload([][]byte{{0xbb}})
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a payload the id does not cover")
		}
	})

	t.Run("nil timeout", func(t *testing.T) {
		if v.VerifyTimeout(nil) {
			t.Error("VerifyTimeout(nil) = true")
		}
	})
	t.Run("timeout without tmo info", func(t *testing.T) {
		if v.VerifyTimeout(diempb.TimeoutMsg_builder{}.Build()) {
			t.Error("VerifyTimeout = true without timeout info")
		}
	})
	t.Run("timeout without a high qc", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.GetTmoInfo().ClearHighQc()
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true without a high qc")
		}
	})
	t.Run("timeout without a signature", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.GetTmoInfo().ClearSig()
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true without a signature")
		}
	})
}

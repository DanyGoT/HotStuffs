// Package diemnet is the Gorums transport for DiemBFT. Three files here see
// protobuf, and nothing else below them does: wire.go converts between the
// generated messages and the domain types, server.go implements the generated
// server interface, and gorums.go calls the generated client functions.
// Package diem itself deals only in domain types, and check-deps enforces
// exactly that.
//
// It is a sibling of package network, which does the same job for package
// consensus. The two are deliberately not generalised into one: the protocols
// share no message, and a vote here is unicast where a vote there is broadcast.
package diemnet

import (
	"errors"
	"fmt"

	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
)

// --- domain to wire ---

func toSig(s diem.Signature) *diempb.Signature {
	return diempb.Signature_builder{
		Signer: uint32(s.Signer),
		Sig:    s.Data,
	}.Build()
}

// toAuthorSig omits the zero signature. Only the genesis certificate has one:
// it is trusted rather than certified, so diem.Verifier.VerifyQC exempts round
// 0 from the author check and every other certificate must carry it.
func toAuthorSig(s diem.Signature) *diempb.Signature {
	if s.Signer == 0 && len(s.Data) == 0 {
		return nil
	}
	return toSig(s)
}

func toSigs(sigs []diem.Signature) []*diempb.Signature {
	out := make([]*diempb.Signature, len(sigs))
	for i, s := range sigs {
		out[i] = toSig(s)
	}
	return out
}

func toVoteInfo(v diem.VoteInfo) *diempb.VoteInfo {
	return diempb.VoteInfo_builder{
		Id:          v.ID[:],
		Round:       uint64(v.Round),
		ParentId:    v.ParentID[:],
		ParentRound: uint64(v.ParentRound),
		ExecStateId: v.ExecStateID[:],
	}.Build()
}

func toCommitInfo(l diem.LedgerCommitInfo) *diempb.LedgerCommitInfo {
	return diempb.LedgerCommitInfo_builder{
		CommitStateId: l.CommitStateID[:],
		VoteInfoHash:  l.VoteInfoHash[:],
	}.Build()
}

func toQC(qc *diem.QC) *diempb.QuorumCert {
	if qc == nil {
		return nil
	}
	return diempb.QuorumCert_builder{
		VoteInfo:         toVoteInfo(qc.VoteInfo),
		LedgerCommitInfo: toCommitInfo(qc.LedgerCommitInfo),
		Signatures:       toSigs(qc.Signatures),
		Author:           uint32(qc.Author),
		AuthorSig:        toAuthorSig(qc.AuthorSig),
	}.Build()
}

func toTC(tc *diem.TC) *diempb.TimeoutCert {
	if tc == nil {
		return nil
	}
	votes := make([]*diempb.TimeoutVote, len(tc.Votes))
	for i, v := range tc.Votes {
		votes[i] = diempb.TimeoutVote_builder{
			HighQcRound: uint64(v.HighQCRound),
			Sig:         toSig(v.Sig),
		}.Build()
	}
	return diempb.TimeoutCert_builder{
		Round: uint64(tc.Round),
		Votes: votes,
	}.Build()
}

func toBlock(b *diem.Block) *diempb.Block {
	if b == nil {
		return nil
	}
	return diempb.Block_builder{
		Author:  uint32(b.Author),
		Round:   uint64(b.Round),
		Payload: b.Payload,
		Qc:      toQC(b.QC),
	}.Build()
}

func toProposal(p *diem.ProposalMsg) *diempb.ProposalMsg {
	return diempb.ProposalMsg_builder{
		Block:        toBlock(p.Block),
		LastRoundTc:  toTC(p.LastRoundTC),
		HighCommitQc: toQC(p.HighCommitQC),
		Sender:       uint32(p.Sender),
		Sig:          toSig(p.Sig),
	}.Build()
}

func toVote(m *diem.VoteMsg) *diempb.VoteMsg {
	return diempb.VoteMsg_builder{
		VoteInfo:         toVoteInfo(m.VoteInfo),
		LedgerCommitInfo: toCommitInfo(m.LedgerCommitInfo),
		HighCommitQc:     toQC(m.HighCommitQC),
		Sender:           uint32(m.Sender),
		Sig:              toSig(m.Sig),
	}.Build()
}

func toTimeout(m *diem.TimeoutMsg) *diempb.TimeoutMsg {
	t := m.TmoInfo
	return diempb.TimeoutMsg_builder{
		TmoInfo: diempb.TimeoutInfo_builder{
			Round:  uint64(t.Round),
			HighQc: toQC(t.HighQC),
			Sender: uint32(t.Sender),
			Sig:    toSig(t.Sig),
		}.Build(),
		LastRoundTc:  toTC(m.LastRoundTC),
		HighCommitQc: toQC(m.HighCommitQC),
	}.Build()
}

// --- wire to domain ---

func fromHash(b []byte) (diem.Hash, error) {
	var h diem.Hash
	if len(b) != 32 {
		return h, fmt.Errorf("hash: want 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return h, nil
}

func fromSig(s *diempb.Signature) (diem.Signature, error) {
	if s == nil {
		return diem.Signature{}, errors.New("signature: nil")
	}
	if s.GetSigner() == 0 {
		return diem.Signature{}, errors.New("signature: signer unset")
	}
	if len(s.GetSig()) == 0 {
		return diem.Signature{}, errors.New("signature: data empty")
	}
	return diem.Signature{
		Signer: diem.ID(s.GetSigner()),
		Data:   s.GetSig(),
	}, nil
}

// fromSigs preserves wire order. The order is not merely cosmetic: a block id
// covers its certificate's signature slice byte for byte (diem's blockID), so
// permuting it here would make the sender's and the receiver's block ids
// disagree. Whether the order is the canonical strictly-increasing one is the
// Verifier's question, not this one.
func fromSigs(sigs []*diempb.Signature) ([]diem.Signature, error) {
	out := make([]diem.Signature, len(sigs))
	for i, s := range sigs {
		sig, err := fromSig(s)
		if err != nil {
			return nil, fmt.Errorf("sig[%d]: %w", i, err)
		}
		out[i] = sig
	}
	return out, nil
}

func fromVoteInfo(v *diempb.VoteInfo) (diem.VoteInfo, error) {
	if v == nil {
		return diem.VoteInfo{}, errors.New("vote info: nil")
	}
	id, err := fromHash(v.GetId())
	if err != nil {
		return diem.VoteInfo{}, fmt.Errorf("vote info id: %w", err)
	}
	parent, err := fromHash(v.GetParentId())
	if err != nil {
		return diem.VoteInfo{}, fmt.Errorf("vote info parent id: %w", err)
	}
	exec, err := fromHash(v.GetExecStateId())
	if err != nil {
		return diem.VoteInfo{}, fmt.Errorf("vote info exec state id: %w", err)
	}
	return diem.VoteInfo{
		ID:          id,
		Round:       diem.Round(v.GetRound()),
		ParentID:    parent,
		ParentRound: diem.Round(v.GetParentRound()),
		ExecStateID: exec,
	}, nil
}

func fromCommitInfo(l *diempb.LedgerCommitInfo) (diem.LedgerCommitInfo, error) {
	if l == nil {
		return diem.LedgerCommitInfo{}, errors.New("ledger commit info: nil")
	}
	state, err := fromHash(l.GetCommitStateId())
	if err != nil {
		return diem.LedgerCommitInfo{}, fmt.Errorf("commit state id: %w", err)
	}
	voteHash, err := fromHash(l.GetVoteInfoHash())
	if err != nil {
		return diem.LedgerCommitInfo{}, fmt.Errorf("vote info hash: %w", err)
	}
	return diem.LedgerCommitInfo{CommitStateID: state, VoteInfoHash: voteHash}, nil
}

// fromQC errors on an absent certificate, where fromTC returns nil: a block's
// QC and a timeout's high QC are never absent, while a nil TC is the paper's
// convention for "the certificate alone justifies the round".
func fromQC(qc *diempb.QuorumCert) (*diem.QC, error) {
	if qc == nil {
		return nil, errors.New("quorum cert: nil")
	}
	voteInfo, err := fromVoteInfo(qc.GetVoteInfo())
	if err != nil {
		return nil, fmt.Errorf("quorum cert: %w", err)
	}
	commit, err := fromCommitInfo(qc.GetLedgerCommitInfo())
	if err != nil {
		return nil, fmt.Errorf("quorum cert: %w", err)
	}
	sigs, err := fromSigs(qc.GetSignatures())
	if err != nil {
		return nil, fmt.Errorf("quorum cert: %w", err)
	}
	// An absent author signature decodes to the zero value rather than an
	// error, because genesis carries none; see toAuthorSig.
	var authorSig diem.Signature
	if qc.HasAuthorSig() {
		if authorSig, err = fromSig(qc.GetAuthorSig()); err != nil {
			return nil, fmt.Errorf("quorum cert author sig: %w", err)
		}
	}
	return &diem.QC{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		Signatures:       sigs,
		Author:           diem.ID(qc.GetAuthor()),
		AuthorSig:        authorSig,
	}, nil
}

func fromTC(tc *diempb.TimeoutCert) (*diem.TC, error) {
	if tc == nil {
		return nil, nil
	}
	votes := make([]diem.TimeoutVote, len(tc.GetVotes()))
	for i, v := range tc.GetVotes() {
		if v == nil {
			return nil, fmt.Errorf("timeout cert vote[%d]: nil", i)
		}
		sig, err := fromSig(v.GetSig())
		if err != nil {
			return nil, fmt.Errorf("timeout cert vote[%d]: %w", i, err)
		}
		votes[i] = diem.TimeoutVote{HighQCRound: diem.Round(v.GetHighQcRound()), Sig: sig}
	}
	return &diem.TC{Round: diem.Round(tc.GetRound()), Votes: votes}, nil
}

func fromBlock(b *diempb.Block) (*diem.Block, error) {
	if b == nil {
		return nil, errors.New("block: nil")
	}
	// Author 0 is genesis and nothing else. Genesis is seeded locally by every
	// replica and is never proposed, so a block that reaches the wire always
	// names the leader of its round, and the rotation numbers replicas from 1.
	if b.GetAuthor() == 0 {
		return nil, errors.New("block: author unset")
	}
	qc, err := fromQC(b.GetQc())
	if err != nil {
		return nil, fmt.Errorf("block qc: %w", err)
	}
	// NewBlock recomputes the id from the fields, so no digest is ever taken
	// from the wire.
	return diem.NewBlock(diem.ID(b.GetAuthor()), diem.Round(b.GetRound()), b.GetPayload(), qc), nil
}

func fromProposal(p *diempb.ProposalMsg) (*diem.ProposalMsg, error) {
	if p == nil {
		return nil, errors.New("proposal: nil")
	}
	if p.GetSender() == 0 {
		return nil, errors.New("proposal: sender unset")
	}
	block, err := fromBlock(p.GetBlock())
	if err != nil {
		return nil, fmt.Errorf("proposal: %w", err)
	}
	tc, err := fromTC(p.GetLastRoundTc())
	if err != nil {
		return nil, fmt.Errorf("proposal: %w", err)
	}
	commitQC, err := fromCommitQC(p.GetHighCommitQc())
	if err != nil {
		return nil, fmt.Errorf("proposal: %w", err)
	}
	sig, err := fromSig(p.GetSig())
	if err != nil {
		return nil, fmt.Errorf("proposal sig: %w", err)
	}
	return &diem.ProposalMsg{
		Block:        block,
		LastRoundTC:  tc,
		HighCommitQC: commitQC,
		Sender:       diem.ID(p.GetSender()),
		Sig:          sig,
	}, nil
}

func fromVote(m *diempb.VoteMsg) (*diem.VoteMsg, error) {
	if m == nil {
		return nil, errors.New("vote: nil")
	}
	if m.GetSender() == 0 {
		return nil, errors.New("vote: sender unset")
	}
	voteInfo, err := fromVoteInfo(m.GetVoteInfo())
	if err != nil {
		return nil, fmt.Errorf("vote: %w", err)
	}
	commit, err := fromCommitInfo(m.GetLedgerCommitInfo())
	if err != nil {
		return nil, fmt.Errorf("vote: %w", err)
	}
	commitQC, err := fromCommitQC(m.GetHighCommitQc())
	if err != nil {
		return nil, fmt.Errorf("vote: %w", err)
	}
	sig, err := fromSig(m.GetSig())
	if err != nil {
		return nil, fmt.Errorf("vote sig: %w", err)
	}
	return &diem.VoteMsg{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commit,
		HighCommitQC:     commitQC,
		Sender:           diem.ID(m.GetSender()),
		Sig:              sig,
	}, nil
}

func fromTimeout(m *diempb.TimeoutMsg) (*diem.TimeoutMsg, error) {
	if m == nil {
		return nil, errors.New("timeout: nil")
	}
	t := m.GetTmoInfo()
	if t == nil {
		return nil, errors.New("timeout: missing timeout info")
	}
	if t.GetSender() == 0 {
		return nil, errors.New("timeout: sender unset")
	}
	highQC, err := fromQC(t.GetHighQc())
	if err != nil {
		return nil, fmt.Errorf("timeout high qc: %w", err)
	}
	sig, err := fromSig(t.GetSig())
	if err != nil {
		return nil, fmt.Errorf("timeout sig: %w", err)
	}
	tc, err := fromTC(m.GetLastRoundTc())
	if err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	commitQC, err := fromCommitQC(m.GetHighCommitQc())
	if err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	return &diem.TimeoutMsg{
		TmoInfo: diem.TimeoutInfo{
			Round:  diem.Round(t.GetRound()),
			HighQC: highQC,
			Sender: diem.ID(t.GetSender()),
			Sig:    sig,
		},
		LastRoundTC:  tc,
		HighCommitQC: commitQC,
	}, nil
}

// fromCommitQC accepts an absent commit certificate: it is a catch-up hint
// every message carries opportunistically, not evidence anything depends on.
func fromCommitQC(qc *diempb.QuorumCert) (*diem.QC, error) {
	if qc == nil {
		return nil, nil
	}
	return fromQC(qc)
}

// Package network is the Gorums transport for HotStuff. wire.go is the only
// file in the package — and the only file in the project — that knows
// protobuf exists: everything below it deals only in domain types.
package network

import (
	"errors"
	"fmt"

	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/hotstuffpb"
)

// --- domain to wire ---

func toSig(s hotstuff.Signature) *hotstuffpb.Signature {
	return hotstuffpb.Signature_builder{
		Signer: uint32(s.Signer),
		Sig:    s.Data,
	}.Build()
}

func toSigs(sigs []hotstuff.Signature) []*hotstuffpb.Signature {
	out := make([]*hotstuffpb.Signature, len(sigs))
	for i, s := range sigs {
		out[i] = toSig(s)
	}
	return out
}

func toQC(qc hotstuff.QuorumCert) *hotstuffpb.QuorumCert {
	return hotstuffpb.QuorumCert_builder{
		View:      uint64(qc.View),
		BlockHash: qc.BlockHash[:],
		Sigs:      toSigs(qc.Sigs),
	}.Build()
}

func toTC(tc *hotstuff.TimeoutCert) *hotstuffpb.TimeoutCert {
	if tc == nil {
		return nil
	}
	return hotstuffpb.TimeoutCert_builder{
		View: uint64(tc.View),
		Sigs: toSigs(tc.Sigs),
	}.Build()
}

func toBlock(b *hotstuff.Block) *hotstuffpb.Block {
	if b == nil {
		return nil
	}
	parent := b.Parent()
	return hotstuffpb.Block_builder{
		Parent:   parent[:],
		View:     uint64(b.View()),
		Proposer: uint32(b.Proposer()),
		Cmds:     b.Cmds(),
		Cert:     toQC(b.QC()),
	}.Build()
}

func toProposal(p hotstuff.Proposal) *hotstuffpb.Proposal {
	return hotstuffpb.Proposal_builder{
		Block: toBlock(p.Block),
		Sig:   toSig(p.Sig),
		Tc:    toTC(p.TC),
	}.Build()
}

func toVote(c hotstuff.PartialCert) *hotstuffpb.VoteMsg {
	return hotstuffpb.VoteMsg_builder{
		View:      uint64(c.View),
		BlockHash: c.BlockHash[:],
		Sig:       toSig(c.Sig),
	}.Build()
}

func toTimeout(m hotstuff.TimeoutMsg) *hotstuffpb.TimeoutMsg {
	return hotstuffpb.TimeoutMsg_builder{
		View:   uint64(m.View),
		Sig:    toSig(m.Sig),
		HighQc: toQC(m.HighQC),
	}.Build()
}

func toBlockHash(h hotstuff.Hash) *hotstuffpb.BlockHash {
	return hotstuffpb.BlockHash_builder{
		Hash: h[:],
	}.Build()
}

// --- wire to domain ---

func fromHash(b []byte) (hotstuff.Hash, error) {
	var h hotstuff.Hash
	if len(b) != 32 {
		return h, fmt.Errorf("hash: want 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return h, nil
}

func fromSig(s *hotstuffpb.Signature) (hotstuff.Signature, error) {
	if s == nil {
		return hotstuff.Signature{}, errors.New("signature: nil")
	}
	if s.GetSigner() == 0 {
		return hotstuff.Signature{}, errors.New("signature: signer unset")
	}
	if len(s.GetSig()) == 0 {
		return hotstuff.Signature{}, errors.New("signature: data empty")
	}
	return hotstuff.Signature{
		Signer: hotstuff.ID(s.GetSigner()),
		Data:   s.GetSig(),
	}, nil
}

func fromSigs(sigs []*hotstuffpb.Signature) ([]hotstuff.Signature, error) {
	out := make([]hotstuff.Signature, len(sigs))
	for i, s := range sigs {
		sig, err := fromSig(s)
		if err != nil {
			return nil, fmt.Errorf("sig[%d]: %w", i, err)
		}
		out[i] = sig
	}
	return out, nil
}

func fromQC(qc *hotstuffpb.QuorumCert) (hotstuff.QuorumCert, error) {
	if qc == nil {
		return hotstuff.QuorumCert{}, errors.New("quorum cert: nil")
	}
	hash, err := fromHash(qc.GetBlockHash())
	if err != nil {
		return hotstuff.QuorumCert{}, fmt.Errorf("quorum cert block hash: %w", err)
	}
	sigs, err := fromSigs(qc.GetSigs())
	if err != nil {
		return hotstuff.QuorumCert{}, fmt.Errorf("quorum cert: %w", err)
	}
	return hotstuff.QuorumCert{
		View:      hotstuff.View(qc.GetView()),
		BlockHash: hash,
		Sigs:      sigs,
	}, nil
}

func fromTC(tc *hotstuffpb.TimeoutCert) (*hotstuff.TimeoutCert, error) {
	if tc == nil {
		return nil, nil
	}
	sigs, err := fromSigs(tc.GetSigs())
	if err != nil {
		return nil, fmt.Errorf("timeout cert: %w", err)
	}
	return &hotstuff.TimeoutCert{
		View: hotstuff.View(tc.GetView()),
		Sigs: sigs,
	}, nil
}

func fromBlock(b *hotstuffpb.Block) (*hotstuff.Block, error) {
	if b == nil {
		return nil, errors.New("block: nil")
	}
	if !b.HasCert() {
		return nil, errors.New("block: missing cert")
	}
	parent, err := fromHash(b.GetParent())
	if err != nil {
		return nil, fmt.Errorf("block parent: %w", err)
	}
	if b.GetProposer() == 0 {
		return nil, errors.New("block: proposer unset")
	}
	qc, err := fromQC(b.GetCert())
	if err != nil {
		return nil, fmt.Errorf("block cert: %w", err)
	}
	// NewBlock recomputes the hash from the fields, so no digest is ever taken
	// from the wire.
	return hotstuff.NewBlock(parent, hotstuff.View(b.GetView()), hotstuff.ID(b.GetProposer()), qc, b.GetCmds()), nil
}

func fromProposal(p *hotstuffpb.Proposal) (hotstuff.Proposal, error) {
	if p == nil {
		return hotstuff.Proposal{}, errors.New("proposal: nil")
	}
	block, err := fromBlock(p.GetBlock())
	if err != nil {
		return hotstuff.Proposal{}, fmt.Errorf("proposal block: %w", err)
	}
	sig, err := fromSig(p.GetSig())
	if err != nil {
		return hotstuff.Proposal{}, fmt.Errorf("proposal sig: %w", err)
	}
	tc, err := fromTC(p.GetTc())
	if err != nil {
		return hotstuff.Proposal{}, fmt.Errorf("proposal tc: %w", err)
	}
	return hotstuff.Proposal{
		Block: block,
		Sig:   sig,
		TC:    tc,
	}, nil
}

func fromVote(v *hotstuffpb.VoteMsg) (hotstuff.PartialCert, error) {
	if v == nil {
		return hotstuff.PartialCert{}, errors.New("vote: nil")
	}
	hash, err := fromHash(v.GetBlockHash())
	if err != nil {
		return hotstuff.PartialCert{}, fmt.Errorf("vote block hash: %w", err)
	}
	sig, err := fromSig(v.GetSig())
	if err != nil {
		return hotstuff.PartialCert{}, fmt.Errorf("vote sig: %w", err)
	}
	return hotstuff.PartialCert{
		View:      hotstuff.View(v.GetView()),
		BlockHash: hash,
		Sig:       sig,
	}, nil
}

func fromTimeout(m *hotstuffpb.TimeoutMsg) (hotstuff.TimeoutMsg, error) {
	if m == nil {
		return hotstuff.TimeoutMsg{}, errors.New("timeout: nil")
	}
	sig, err := fromSig(m.GetSig())
	if err != nil {
		return hotstuff.TimeoutMsg{}, fmt.Errorf("timeout sig: %w", err)
	}
	if m.GetHighQc() == nil {
		return hotstuff.TimeoutMsg{}, errors.New("timeout: missing high qc")
	}
	qc, err := fromQC(m.GetHighQc())
	if err != nil {
		return hotstuff.TimeoutMsg{}, fmt.Errorf("timeout high qc: %w", err)
	}
	return hotstuff.TimeoutMsg{
		View:   hotstuff.View(m.GetView()),
		Sig:    sig,
		HighQC: qc,
	}, nil
}

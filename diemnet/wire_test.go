package diemnet

import (
	"strings"
	"testing"

	"github.com/DanyGoT/HotStuffs/crypto/nocrypto"
	"github.com/DanyGoT/HotStuffs/diem"
	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/diempb"
	"google.golang.org/protobuf/proto"
)

func sig(id diem.ID, data string) diem.Signature {
	return diem.Signature{Signer: id, Data: []byte(data)}
}

func mustHash(b byte) diem.Hash {
	var h diem.Hash
	h[0] = b
	return h
}

// marshalled sends in through protobuf and back, so every round trip below is
// over the real encoding rather than over the builders alone.
func marshalled[T proto.Message](t *testing.T, in, out T) T {
	t.Helper()
	buf, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := proto.Unmarshal(buf, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func eqSig(t *testing.T, got, want diem.Signature) {
	t.Helper()
	if got.Signer != want.Signer || string(got.Data) != string(want.Data) {
		t.Errorf("signature = %+v, want %+v", got, want)
	}
}

func eqSigs(t *testing.T, got, want []diem.Signature) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("signatures len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		eqSig(t, got[i], want[i])
	}
}

func eqVoteInfo(t *testing.T, got, want diem.VoteInfo) {
	t.Helper()
	if got != want {
		t.Errorf("vote info = %+v, want %+v", got, want)
	}
}

func eqQC(t *testing.T, got, want *diem.QC) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("qc = %v, want %v", got, want)
	}
	if got == nil {
		return
	}
	eqVoteInfo(t, got.VoteInfo, want.VoteInfo)
	if got.LedgerCommitInfo != want.LedgerCommitInfo {
		t.Errorf("qc.LedgerCommitInfo = %+v, want %+v", got.LedgerCommitInfo, want.LedgerCommitInfo)
	}
	eqSigs(t, got.Signatures, want.Signatures)
	if got.Author != want.Author {
		t.Errorf("qc.Author = %d, want %d", got.Author, want.Author)
	}
	eqSig(t, got.AuthorSig, want.AuthorSig)
}

func eqTC(t *testing.T, got, want *diem.TC) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("tc = %v, want %v", got, want)
	}
	if got == nil {
		return
	}
	if got.Round != want.Round {
		t.Errorf("tc.Round = %d, want %d", got.Round, want.Round)
	}
	if len(got.Votes) != len(want.Votes) {
		t.Fatalf("tc.Votes len = %d, want %d", len(got.Votes), len(want.Votes))
	}
	for i := range want.Votes {
		if got.Votes[i].HighQCRound != want.Votes[i].HighQCRound {
			t.Errorf("tc.Votes[%d].HighQCRound = %d, want %d", i, got.Votes[i].HighQCRound, want.Votes[i].HighQCRound)
		}
		eqSig(t, got.Votes[i].Sig, want.Votes[i].Sig)
	}
}

// eqBlock compares every field plus the recomputed id. The id is the assertion
// that matters: it is computed independently on each side, and a chain forks
// the moment the two disagree.
func eqBlock(t *testing.T, got, want *diem.Block) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("block = %v, want %v", got, want)
	}
	if got == nil {
		return
	}
	if got.Author != want.Author || got.Round != want.Round {
		t.Errorf("block = {Author:%d Round:%d}, want {Author:%d Round:%d}",
			got.Author, got.Round, want.Author, want.Round)
	}
	if len(got.Payload) != len(want.Payload) {
		t.Fatalf("block payload len = %d, want %d", len(got.Payload), len(want.Payload))
	}
	for i := range want.Payload {
		if string(got.Payload[i]) != string(want.Payload[i]) {
			t.Errorf("block payload[%d] = %q, want %q", i, got.Payload[i], want.Payload[i])
		}
	}
	eqQC(t, got.QC, want.QC)
	if got.ID() != want.ID() {
		t.Errorf("block id = %x, want %x", got.ID(), want.ID())
	}
}

func sampleVoteInfo() diem.VoteInfo {
	return diem.VoteInfo{
		ID:          mustHash(1),
		Round:       7,
		ParentID:    mustHash(2),
		ParentRound: 6,
		ExecStateID: mustHash(3),
	}
}

func sampleCommitInfo(v diem.VoteInfo) diem.LedgerCommitInfo {
	return diem.LedgerCommitInfo{CommitStateID: mustHash(4), VoteInfoHash: diem.VoteInfoHash(v)}
}

// sampleQC carries three signers in the canonical strictly-increasing order the
// Verifier insists on.
func sampleQC() *diem.QC {
	v := sampleVoteInfo()
	return &diem.QC{
		VoteInfo:         v,
		LedgerCommitInfo: sampleCommitInfo(v),
		Signatures:       []diem.Signature{sig(1, "s1"), sig(2, "s2"), sig(3, "s3")},
		Author:           2,
		AuthorSig:        sig(2, "author"),
	}
}

func sampleTC() *diem.TC {
	return &diem.TC{Round: 7, Votes: []diem.TimeoutVote{
		{HighQCRound: 5, Sig: sig(1, "t1")},
		{HighQCRound: 6, Sig: sig(2, "t2")},
		{HighQCRound: 6, Sig: sig(3, "t3")},
	}}
}

func sampleBlock() *diem.Block {
	return diem.NewBlock(3, 8, [][]byte{[]byte("tx1"), []byte("tx2")}, sampleQC())
}

func TestRoundTrip(t *testing.T) {
	t.Run("block", func(t *testing.T) {
		want := sampleBlock()
		got, err := fromBlock(marshalled(t, toBlock(want), &diempb.Block{}))
		if err != nil {
			t.Fatal(err)
		}
		eqBlock(t, got, want)
	})

	t.Run("proposal", func(t *testing.T) {
		want := &diem.ProposalMsg{
			Block:        sampleBlock(),
			LastRoundTC:  sampleTC(),
			HighCommitQC: sampleQC(),
			Sender:       3,
			Sig:          sig(3, "proposal"),
		}
		got, err := fromProposal(marshalled(t, toProposal(want), &diempb.ProposalMsg{}))
		if err != nil {
			t.Fatal(err)
		}
		eqBlock(t, got.Block, want.Block)
		eqTC(t, got.LastRoundTC, want.LastRoundTC)
		eqQC(t, got.HighCommitQC, want.HighCommitQC)
		if got.Sender != want.Sender {
			t.Errorf("sender = %d, want %d", got.Sender, want.Sender)
		}
		eqSig(t, got.Sig, want.Sig)
	})

	t.Run("proposal with no tc and no commit qc", func(t *testing.T) {
		want := &diem.ProposalMsg{Block: sampleBlock(), Sender: 3, Sig: sig(3, "proposal")}
		got, err := fromProposal(marshalled(t, toProposal(want), &diempb.ProposalMsg{}))
		if err != nil {
			t.Fatal(err)
		}
		if got.LastRoundTC != nil {
			t.Errorf("LastRoundTC = %+v, want nil", got.LastRoundTC)
		}
		if got.HighCommitQC != nil {
			t.Errorf("HighCommitQC = %+v, want nil", got.HighCommitQC)
		}
	})

	t.Run("vote", func(t *testing.T) {
		v := sampleVoteInfo()
		want := &diem.VoteMsg{
			VoteInfo:         v,
			LedgerCommitInfo: sampleCommitInfo(v),
			HighCommitQC:     sampleQC(),
			Sender:           4,
			Sig:              sig(4, "vote"),
		}
		got, err := fromVote(marshalled(t, toVote(want), &diempb.VoteMsg{}))
		if err != nil {
			t.Fatal(err)
		}
		eqVoteInfo(t, got.VoteInfo, want.VoteInfo)
		if got.LedgerCommitInfo != want.LedgerCommitInfo {
			t.Errorf("commit info = %+v, want %+v", got.LedgerCommitInfo, want.LedgerCommitInfo)
		}
		eqQC(t, got.HighCommitQC, want.HighCommitQC)
		if got.Sender != want.Sender {
			t.Errorf("sender = %d, want %d", got.Sender, want.Sender)
		}
		eqSig(t, got.Sig, want.Sig)
	})

	t.Run("timeout", func(t *testing.T) {
		want := &diem.TimeoutMsg{
			TmoInfo: diem.TimeoutInfo{
				Round:  8,
				HighQC: sampleQC(),
				Sender: 2,
				Sig:    sig(2, "timeout"),
			},
			LastRoundTC:  sampleTC(),
			HighCommitQC: sampleQC(),
		}
		got, err := fromTimeout(marshalled(t, toTimeout(want), &diempb.TimeoutMsg{}))
		if err != nil {
			t.Fatal(err)
		}
		if got.TmoInfo.Round != want.TmoInfo.Round || got.TmoInfo.Sender != want.TmoInfo.Sender {
			t.Errorf("tmo info = %+v, want %+v", got.TmoInfo, want.TmoInfo)
		}
		eqQC(t, got.TmoInfo.HighQC, want.TmoInfo.HighQC)
		eqSig(t, got.TmoInfo.Sig, want.TmoInfo.Sig)
		eqTC(t, got.LastRoundTC, want.LastRoundTC)
		eqQC(t, got.HighCommitQC, want.HighCommitQC)
	})

	t.Run("timeout with no tc and no commit qc", func(t *testing.T) {
		want := &diem.TimeoutMsg{TmoInfo: diem.TimeoutInfo{
			Round: 8, HighQC: sampleQC(), Sender: 2, Sig: sig(2, "timeout"),
		}}
		got, err := fromTimeout(marshalled(t, toTimeout(want), &diempb.TimeoutMsg{}))
		if err != nil {
			t.Fatal(err)
		}
		if got.LastRoundTC != nil || got.HighCommitQC != nil {
			t.Errorf("tc = %v, commit qc = %v, want both nil", got.LastRoundTC, got.HighCommitQC)
		}
	})
}

// TestSignatureOrderSurvives is the round trip that safety depends on. A block
// id covers its certificate's signature slice byte for byte, so a wire layer
// that sorted, deduplicated or otherwise permuted the set would hand the
// receiver a different block id for the same block, and the chain would fork.
//
// The permuted case is the one with teeth: the encoding must be faithful, not
// merely canonical. It is checked by asserting that the two orders really do
// produce different ids, so the equality in the canonical case is evidence and
// not a tautology.
func TestSignatureOrderSurvives(t *testing.T) {
	sigs := []diem.Signature{sig(1, "s1"), sig(2, "s2"), sig(3, "s3")}
	orders := map[string][]int{
		"canonical": {0, 1, 2},
		"permuted":  {2, 0, 1},
		"reversed":  {2, 1, 0},
	}

	ids := map[string]diem.Hash{}
	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			qc := sampleQC()
			qc.Signatures = make([]diem.Signature, len(order))
			for i, j := range order {
				qc.Signatures[i] = sigs[j]
			}
			want := diem.NewBlock(3, 8, [][]byte{[]byte("tx")}, qc)

			got, err := fromBlock(marshalled(t, toBlock(want), &diempb.Block{}))
			if err != nil {
				t.Fatal(err)
			}
			eqSigs(t, got.QC.Signatures, qc.Signatures)
			if got.ID() != want.ID() {
				t.Fatalf("block id = %x, want %x: the signature order did not survive", got.ID(), want.ID())
			}
			ids[name] = got.ID()
		})
	}

	if ids["canonical"] == ids["permuted"] || ids["canonical"] == ids["reversed"] {
		t.Fatal("a permuted signature set produced the same block id, so the ids prove nothing")
	}
}

// TestGenesisQCRoundTrips: genesis carries no author signature and no quorum,
// and must still decode into something the Verifier accepts — a replica's very
// first proposal extends it.
func TestGenesisQCRoundTrips(t *testing.T) {
	want := diem.GenesisQC()
	got, err := fromQC(marshalled(t, toQC(want), &diempb.QuorumCert{}))
	if err != nil {
		t.Fatal(err)
	}
	eqQC(t, got, want)
	if len(got.Signatures) != 0 {
		t.Errorf("signatures = %d, want 0", len(got.Signatures))
	}
	if !diem.NewVerifier(nocrypto.New(1, 4), hotstuff.QuorumSize(4)).VerifyQC(got) {
		t.Error("the Verifier rejected a round-tripped genesis certificate")
	}
}

func TestMalformed(t *testing.T) {
	goodSig := diempb.Signature_builder{Signer: 1, Sig: []byte("s")}.Build()
	goodQC := toQC(sampleQC())
	shortHash := []byte{0x01}

	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{"nil signature", func() error {
			_, err := fromSig(nil)
			return err
		}, "signature: nil"},
		{"signer 0", func() error {
			_, err := fromSig(diempb.Signature_builder{Sig: []byte("s")}.Build())
			return err
		}, "signer unset"},
		{"empty signature data", func() error {
			_, err := fromSig(diempb.Signature_builder{Signer: 1}.Build())
			return err
		}, "data empty"},
		{"nil vote info", func() error {
			_, err := fromVoteInfo(nil)
			return err
		}, "vote info: nil"},
		{"short vote info id", func() error {
			_, err := fromVoteInfo(diempb.VoteInfo_builder{Id: shortHash}.Build())
			return err
		}, "vote info id"},
		{"short vote info parent id", func() error {
			h := mustHash(1)
			_, err := fromVoteInfo(diempb.VoteInfo_builder{Id: h[:], ParentId: shortHash}.Build())
			return err
		}, "parent id"},
		{"short vote info exec state id", func() error {
			h := mustHash(1)
			_, err := fromVoteInfo(diempb.VoteInfo_builder{Id: h[:], ParentId: h[:], ExecStateId: shortHash}.Build())
			return err
		}, "exec state id"},
		{"nil ledger commit info", func() error {
			_, err := fromCommitInfo(nil)
			return err
		}, "ledger commit info: nil"},
		{"short commit state id", func() error {
			_, err := fromCommitInfo(diempb.LedgerCommitInfo_builder{CommitStateId: shortHash}.Build())
			return err
		}, "commit state id"},
		{"short vote info hash", func() error {
			h := mustHash(1)
			_, err := fromCommitInfo(diempb.LedgerCommitInfo_builder{CommitStateId: h[:], VoteInfoHash: shortHash}.Build())
			return err
		}, "vote info hash"},
		{"nil quorum cert", func() error {
			_, err := fromQC(nil)
			return err
		}, "quorum cert: nil"},
		{"quorum cert without vote info", func() error {
			_, err := fromQC(diempb.QuorumCert_builder{}.Build())
			return err
		}, "vote info"},
		{"quorum cert without commit info", func() error {
			_, err := fromQC(diempb.QuorumCert_builder{VoteInfo: toVoteInfo(sampleVoteInfo())}.Build())
			return err
		}, "ledger commit info"},
		{"quorum cert with a malformed signature", func() error {
			v := sampleVoteInfo()
			_, err := fromQC(diempb.QuorumCert_builder{
				VoteInfo:         toVoteInfo(v),
				LedgerCommitInfo: toCommitInfo(sampleCommitInfo(v)),
				Signatures:       []*diempb.Signature{diempb.Signature_builder{Signer: 0}.Build()},
			}.Build())
			return err
		}, "sig[0]"},
		{"quorum cert with a malformed author signature", func() error {
			v := sampleVoteInfo()
			_, err := fromQC(diempb.QuorumCert_builder{
				VoteInfo:         toVoteInfo(v),
				LedgerCommitInfo: toCommitInfo(sampleCommitInfo(v)),
				AuthorSig:        diempb.Signature_builder{Signer: 2}.Build(),
			}.Build())
			return err
		}, "author sig"},
		{"timeout cert with a nil vote", func() error {
			_, err := fromTC(diempb.TimeoutCert_builder{Round: 3, Votes: []*diempb.TimeoutVote{nil}}.Build())
			return err
		}, "vote[0]: nil"},
		{"timeout cert with a malformed signature", func() error {
			_, err := fromTC(diempb.TimeoutCert_builder{Round: 3, Votes: []*diempb.TimeoutVote{
				diempb.TimeoutVote_builder{HighQcRound: 2}.Build(),
			}}.Build())
			return err
		}, "vote[0]"},
		{"nil block", func() error {
			_, err := fromBlock(nil)
			return err
		}, "block: nil"},
		{"block author 0", func() error {
			_, err := fromBlock(diempb.Block_builder{Round: 1, Qc: goodQC}.Build())
			return err
		}, "author unset"},
		{"block without a qc", func() error {
			_, err := fromBlock(diempb.Block_builder{Author: 1, Round: 1}.Build())
			return err
		}, "block qc"},
		{"nil proposal", func() error {
			_, err := fromProposal(nil)
			return err
		}, "proposal: nil"},
		{"proposal sender 0", func() error {
			_, err := fromProposal(diempb.ProposalMsg_builder{Block: toBlock(sampleBlock()), Sig: goodSig}.Build())
			return err
		}, "sender unset"},
		{"proposal without a block", func() error {
			_, err := fromProposal(diempb.ProposalMsg_builder{Sender: 1, Sig: goodSig}.Build())
			return err
		}, "block: nil"},
		{"proposal with a malformed tc", func() error {
			_, err := fromProposal(diempb.ProposalMsg_builder{
				Block:       toBlock(sampleBlock()),
				LastRoundTc: diempb.TimeoutCert_builder{Round: 1, Votes: []*diempb.TimeoutVote{nil}}.Build(),
				Sender:      1, Sig: goodSig,
			}.Build())
			return err
		}, "vote[0]: nil"},
		{"proposal with a malformed commit qc", func() error {
			_, err := fromProposal(diempb.ProposalMsg_builder{
				Block:        toBlock(sampleBlock()),
				HighCommitQc: diempb.QuorumCert_builder{}.Build(),
				Sender:       1, Sig: goodSig,
			}.Build())
			return err
		}, "vote info"},
		{"proposal without a signature", func() error {
			_, err := fromProposal(diempb.ProposalMsg_builder{Block: toBlock(sampleBlock()), Sender: 1}.Build())
			return err
		}, "proposal sig"},
		{"nil vote", func() error {
			_, err := fromVote(nil)
			return err
		}, "vote: nil"},
		{"vote sender 0", func() error {
			_, err := fromVote(diempb.VoteMsg_builder{Sig: goodSig}.Build())
			return err
		}, "sender unset"},
		{"vote without vote info", func() error {
			_, err := fromVote(diempb.VoteMsg_builder{Sender: 1, Sig: goodSig}.Build())
			return err
		}, "vote info: nil"},
		{"vote without commit info", func() error {
			_, err := fromVote(diempb.VoteMsg_builder{
				VoteInfo: toVoteInfo(sampleVoteInfo()), Sender: 1, Sig: goodSig,
			}.Build())
			return err
		}, "ledger commit info: nil"},
		{"vote with a malformed commit qc", func() error {
			v := sampleVoteInfo()
			_, err := fromVote(diempb.VoteMsg_builder{
				VoteInfo:         toVoteInfo(v),
				LedgerCommitInfo: toCommitInfo(sampleCommitInfo(v)),
				HighCommitQc:     diempb.QuorumCert_builder{}.Build(),
				Sender:           1, Sig: goodSig,
			}.Build())
			return err
		}, "vote info"},
		{"vote without a signature", func() error {
			v := sampleVoteInfo()
			_, err := fromVote(diempb.VoteMsg_builder{
				VoteInfo:         toVoteInfo(v),
				LedgerCommitInfo: toCommitInfo(sampleCommitInfo(v)),
				Sender:           1,
			}.Build())
			return err
		}, "vote sig"},
		{"nil timeout", func() error {
			_, err := fromTimeout(nil)
			return err
		}, "timeout: nil"},
		{"timeout without tmo info", func() error {
			_, err := fromTimeout(diempb.TimeoutMsg_builder{}.Build())
			return err
		}, "missing timeout info"},
		{"timeout sender 0", func() error {
			_, err := fromTimeout(diempb.TimeoutMsg_builder{
				TmoInfo: diempb.TimeoutInfo_builder{Round: 1, HighQc: goodQC, Sig: goodSig}.Build(),
			}.Build())
			return err
		}, "sender unset"},
		{"timeout without a high qc", func() error {
			_, err := fromTimeout(diempb.TimeoutMsg_builder{
				TmoInfo: diempb.TimeoutInfo_builder{Round: 1, Sender: 1, Sig: goodSig}.Build(),
			}.Build())
			return err
		}, "timeout high qc"},
		{"timeout without a signature", func() error {
			_, err := fromTimeout(diempb.TimeoutMsg_builder{
				TmoInfo: diempb.TimeoutInfo_builder{Round: 1, HighQc: goodQC, Sender: 1}.Build(),
			}.Build())
			return err
		}, "timeout sig"},
		{"timeout with a malformed tc", func() error {
			_, err := fromTimeout(diempb.TimeoutMsg_builder{
				TmoInfo:     diempb.TimeoutInfo_builder{Round: 1, HighQc: goodQC, Sender: 1, Sig: goodSig}.Build(),
				LastRoundTc: diempb.TimeoutCert_builder{Round: 1, Votes: []*diempb.TimeoutVote{nil}}.Build(),
			}.Build())
			return err
		}, "vote[0]: nil"},
		{"timeout with a malformed commit qc", func() error {
			_, err := fromTimeout(diempb.TimeoutMsg_builder{
				TmoInfo:      diempb.TimeoutInfo_builder{Round: 1, HighQc: goodQC, Sender: 1, Sig: goodSig}.Build(),
				HighCommitQc: diempb.QuorumCert_builder{}.Build(),
			}.Build())
			return err
		}, "vote info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("got nil error, want a rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestNilPassthrough: the three places where absence is the protocol's own
// convention rather than a malformed message.
func TestNilPassthrough(t *testing.T) {
	if got := toQC(nil); got != nil {
		t.Errorf("toQC(nil) = %v, want nil", got)
	}
	if got := toTC(nil); got != nil {
		t.Errorf("toTC(nil) = %v, want nil", got)
	}
	if got := toBlock(nil); got != nil {
		t.Errorf("toBlock(nil) = %v, want nil", got)
	}
	tc, err := fromTC(nil)
	if tc != nil || err != nil {
		t.Errorf("fromTC(nil) = (%v, %v), want (nil, nil)", tc, err)
	}
	qc, err := fromCommitQC(nil)
	if qc != nil || err != nil {
		t.Errorf("fromCommitQC(nil) = (%v, %v), want (nil, nil)", qc, err)
	}
}

package network

import (
	"strconv"
	"strings"
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
	"github.com/DanyGoT/HotStuffs/proto/hotstuffpb"
)

func sig(id hotstuff.ID, data string) hotstuff.Signature {
	return hotstuff.Signature{Signer: id, Data: []byte(data)}
}

func mustHash(b byte) hotstuff.Hash {
	var h hotstuff.Hash
	h[0] = b
	return h
}

func eqSig(t *testing.T, got, want hotstuff.Signature) {
	t.Helper()
	if got.Signer != want.Signer || string(got.Data) != string(want.Data) {
		t.Errorf("signature = %+v, want %+v", got, want)
	}
}

func eqSigs(t *testing.T, got, want []hotstuff.Signature) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("signatures len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		eqSig(t, got[i], want[i])
	}
}

func eqQC(t *testing.T, got, want hotstuff.QuorumCert) {
	t.Helper()
	if got.View != want.View || got.BlockHash != want.BlockHash {
		t.Errorf("qc = {View:%d BlockHash:%x}, want {View:%d BlockHash:%x}",
			got.View, got.BlockHash, want.View, want.BlockHash)
	}
	eqSigs(t, got.Sigs, want.Sigs)
}

func eqTC(t *testing.T, got, want *hotstuff.TimeoutCert) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("tc = %v, want %v", got, want)
	}
	if got == nil {
		return
	}
	if got.View != want.View {
		t.Errorf("tc.View = %d, want %d", got.View, want.View)
	}
	eqSigs(t, got.Sigs, want.Sigs)
}

// eqBlock compares every field plus the cached hash: the hash is what makes
// the wire form safe to re-hash on Fetch, so it is asserted everywhere a block
// crosses the wire, not just here.
func eqBlock(t *testing.T, got, want *hotstuff.Block) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("block = %v, want %v", got, want)
	}
	if got == nil {
		return
	}
	if got.Parent() != want.Parent() {
		t.Errorf("block.Parent = %x, want %x", got.Parent(), want.Parent())
	}
	if got.View() != want.View() {
		t.Errorf("block.View = %d, want %d", got.View(), want.View())
	}
	if got.Proposer() != want.Proposer() {
		t.Errorf("block.Proposer = %d, want %d", got.Proposer(), want.Proposer())
	}
	if len(got.Cmds()) != len(want.Cmds()) {
		t.Fatalf("block.Cmds len = %d, want %d", len(got.Cmds()), len(want.Cmds()))
	}
	for i := range want.Cmds() {
		if string(got.Cmds()[i]) != string(want.Cmds()[i]) {
			t.Errorf("block.Cmds[%d] = %q, want %q", i, got.Cmds()[i], want.Cmds()[i])
		}
	}
	eqQC(t, got.QC(), want.QC())
	if got.Hash() != want.Hash() {
		t.Errorf("block.Hash() = %x, want %x", got.Hash(), want.Hash())
	}
}

// genesisQC is the only valid view-0 QC: genesis hash, no signatures.
func genesisQC() hotstuff.QuorumCert {
	return hotstuff.QuorumCert{BlockHash: hotstuff.GenesisHash()}
}

func genesisHashBytes() []byte {
	h := hotstuff.GenesisHash()
	return h[:]
}

func twoSigQC() hotstuff.QuorumCert {
	return hotstuff.QuorumCert{
		View:      3,
		BlockHash: mustHash(0xAA),
		Sigs:      []hotstuff.Signature{sig(1, "a"), sig(2, "b")},
	}
}

func blockNoCmds(proposer hotstuff.ID) *hotstuff.Block {
	return hotstuff.NewBlock(hotstuff.GenesisHash(), 1, proposer, genesisQC(), nil)
}

func blockWithCmds(proposer hotstuff.ID) *hotstuff.Block {
	return hotstuff.NewBlock(hotstuff.GenesisHash(), 1, proposer, genesisQC(),
		[][]byte{[]byte("cmd1"), {}, []byte("cmd3")})
}

// TestRoundTrip sends every message kind through from(to(v)), field by
// field, plus Block.Hash() wherever a block is involved.
func TestRoundTrip(t *testing.T) {
	tcVal := &hotstuff.TimeoutCert{View: 2, Sigs: []hotstuff.Signature{sig(1, "t")}}

	t.Run("block with several commands, one empty", func(t *testing.T) {
		want := blockWithCmds(2)
		got, err := fromBlock(toBlock(want))
		if err != nil {
			t.Fatal(err)
		}
		eqBlock(t, got, want)
	})

	t.Run("block with no commands", func(t *testing.T) {
		want := blockNoCmds(2)
		got, err := fromBlock(toBlock(want))
		if err != nil {
			t.Fatal(err)
		}
		eqBlock(t, got, want)
	})

	t.Run("QC with two signatures", func(t *testing.T) {
		want := twoSigQC()
		got, err := fromQC(toQC(want))
		if err != nil {
			t.Fatal(err)
		}
		eqQC(t, got, want)
	})

	t.Run("TC", func(t *testing.T) {
		got, err := fromTC(toTC(tcVal))
		if err != nil {
			t.Fatal(err)
		}
		eqTC(t, got, tcVal)
	})

	t.Run("proposal with a TC", func(t *testing.T) {
		want := hotstuff.Proposal{Block: blockWithCmds(2), Sig: sig(2, "psig"), TC: tcVal}
		got, err := fromProposal(toProposal(want))
		if err != nil {
			t.Fatal(err)
		}
		eqBlock(t, got.Block, want.Block)
		eqSig(t, got.Sig, want.Sig)
		eqTC(t, got.TC, want.TC)
	})

	t.Run("proposal without a TC", func(t *testing.T) {
		want := hotstuff.Proposal{Block: blockNoCmds(2), Sig: sig(2, "psig")}
		got, err := fromProposal(toProposal(want))
		if err != nil {
			t.Fatal(err)
		}
		eqBlock(t, got.Block, want.Block)
		eqSig(t, got.Sig, want.Sig)
		eqTC(t, got.TC, want.TC)
	})

	t.Run("vote", func(t *testing.T) {
		want := hotstuff.PartialCert{View: 1, BlockHash: mustHash(0x11), Sig: sig(3, "v")}
		got, err := fromVote(toVote(want))
		if err != nil {
			t.Fatal(err)
		}
		if got.View != want.View || got.BlockHash != want.BlockHash {
			t.Errorf("vote = %+v, want %+v", got, want)
		}
		eqSig(t, got.Sig, want.Sig)
	})

	t.Run("timeout carrying the genesis QC", func(t *testing.T) {
		want := hotstuff.TimeoutMsg{View: 4, Sig: sig(1, "to"), HighQC: genesisQC()}
		got, err := fromTimeout(toTimeout(want))
		if err != nil {
			t.Fatal(err)
		}
		if got.View != want.View {
			t.Errorf("timeout.View = %d, want %d", got.View, want.View)
		}
		eqSig(t, got.Sig, want.Sig)
		eqQC(t, got.HighQC, want.HighQC)
	})

	t.Run("block hash", func(t *testing.T) {
		want := mustHash(0x42)
		bh := toBlockHash(want)
		got, err := fromHash(bh.GetHash())
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("hash = %x, want %x", got, want)
		}
	})
}

// TestNilPassthrough pins toTC/fromTC and toBlock/toProposal on nil.
func TestNilPassthrough(t *testing.T) {
	if got := toTC(nil); got != nil {
		t.Errorf("toTC(nil) = %v, want nil", got)
	}
	got, err := fromTC(nil)
	if got != nil || err != nil {
		t.Errorf("fromTC(nil) = (%v, %v), want (nil, nil)", got, err)
	}
	if b := toBlock(nil); b != nil {
		t.Errorf("toBlock(nil) = %v, want nil", b)
	}

	// A zero Proposal has a nil Block; toProposal must not panic on it.
	msg := toProposal(hotstuff.Proposal{})
	if msg.GetBlock() != nil {
		t.Errorf("toProposal(zero).Block = %v, want nil", msg.GetBlock())
	}
}

// TestMalformed is the shape errors the converters reject, and the
// boundary rows that must succeed because they are the verifier's job, not
// the converter's.
func TestMalformed(t *testing.T) {
	validSig := hotstuffpb.Signature_builder{Signer: 1, Sig: []byte("s")}.Build()
	validCert := hotstuffpb.QuorumCert_builder{BlockHash: genesisHashBytes()}.Build()

	badHash := make([]byte, 31)

	tests := []struct {
		name    string
		wantErr bool
		run     func() error
	}{
		{"fromSig: nil message", true, func() error {
			_, err := fromSig(nil)
			return err
		}},
		{"fromSig: signer unset", true, func() error {
			_, err := fromSig(hotstuffpb.Signature_builder{Signer: 0, Sig: []byte("s")}.Build())
			return err
		}},
		{"fromSig: empty data", true, func() error {
			_, err := fromSig(hotstuffpb.Signature_builder{Signer: 1, Sig: nil}.Build())
			return err
		}},
		{"fromQC: nil message", true, func() error {
			_, err := fromQC(nil)
			return err
		}},
		{"fromQC: bad block hash", true, func() error {
			_, err := fromQC(hotstuffpb.QuorumCert_builder{BlockHash: badHash}.Build())
			return err
		}},
		{"fromQC: bad signature in list", true, func() error {
			_, err := fromQC(hotstuffpb.QuorumCert_builder{
				BlockHash: genesisHashBytes(),
				Sigs:      []*hotstuffpb.Signature{hotstuffpb.Signature_builder{Signer: 0}.Build()},
			}.Build())
			return err
		}},
		// The verifier, not the converter, owns quorum size: an empty signature
		// list is the genesis QC's shape and must be accepted here.
		{"fromQC: empty signature list is valid (genesis QC shape)", false, func() error {
			_, err := fromQC(hotstuffpb.QuorumCert_builder{BlockHash: genesisHashBytes()}.Build())
			return err
		}},
		// view == 0 is a semantic check (VerifyQC), not a shape check.
		{"fromQC: view 0 is valid shape", false, func() error {
			_, err := fromQC(hotstuffpb.QuorumCert_builder{View: 0, BlockHash: genesisHashBytes()}.Build())
			return err
		}},
		{"fromTC: nil gives (nil, nil)", false, func() error {
			tc, err := fromTC(nil)
			if tc != nil {
				t.Errorf("fromTC(nil) block = %v, want nil", tc)
			}
			return err
		}},
		// Quorum size for a TC's signature list is the verifier's job.
		{"fromTC: empty signature list is valid shape", false, func() error {
			_, err := fromTC(hotstuffpb.TimeoutCert_builder{View: 1}.Build())
			return err
		}},
		{"fromBlock: nil message", true, func() error {
			_, err := fromBlock(nil)
			return err
		}},
		{"fromBlock: missing cert", true, func() error {
			_, err := fromBlock(hotstuffpb.Block_builder{
				Parent: genesisHashBytes(), Proposer: 1,
			}.Build())
			return err
		}},
		{"fromBlock: bad parent hash", true, func() error {
			_, err := fromBlock(hotstuffpb.Block_builder{
				Parent: badHash, Proposer: 1, Cert: validCert,
			}.Build())
			return err
		}},
		{"fromBlock: proposer unset above genesis", true, func() error {
			// Proposer 0 belongs to genesis alone, and genesis is at view 0.
			_, err := fromBlock(hotstuffpb.Block_builder{
				Parent: genesisHashBytes(), View: 1, Proposer: 0, Cert: validCert,
			}.Build())
			return err
		}},
		{"fromProposal: nil message", true, func() error {
			_, err := fromProposal(nil)
			return err
		}},
		{"fromProposal: sub-converter rejects nil block", true, func() error {
			_, err := fromProposal(hotstuffpb.Proposal_builder{Sig: validSig}.Build())
			return err
		}},
		{"fromVote: nil message", true, func() error {
			_, err := fromVote(nil)
			return err
		}},
		{"fromVote: sub-converter rejects bad block hash", true, func() error {
			_, err := fromVote(hotstuffpb.VoteMsg_builder{BlockHash: badHash, Sig: validSig}.Build())
			return err
		}},
		{"fromTimeout: nil message", true, func() error {
			_, err := fromTimeout(nil)
			return err
		}},
		{"fromTimeout: nil HighQc", true, func() error {
			_, err := fromTimeout(hotstuffpb.TimeoutMsg_builder{View: 1, Sig: validSig}.Build())
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if tt.wantErr && err == nil {
				t.Error("got nil error, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}

// TestHashLength checks any length but 32 fails, and the message names it.
func TestHashLength(t *testing.T) {
	for _, n := range []int{0, 33} {
		t.Run(strconv.Itoa(n)+" bytes", func(t *testing.T) {
			_, err := fromHash(make([]byte, n))
			if err == nil {
				t.Fatal("got nil error, want non-nil")
			}
			if !strings.Contains(err.Error(), strconv.Itoa(n)) {
				t.Errorf("error %q does not mention length %d", err.Error(), n)
			}
		})
	}
}

// TestGenesisRoundTrips covers the one block whose proposer is 0. Genesis is
// seeded locally by every store, so it is never actually fetched, but the
// Fetch responder serves whatever the store holds — and an answer this side
// could not decode would be a silent backfill failure.
func TestGenesisRoundTrips(t *testing.T) {
	got, err := fromBlock(toBlock(hotstuff.Genesis()))
	if err != nil {
		t.Fatalf("fromBlock(toBlock(Genesis())) = %v", err)
	}
	if got.Hash() != hotstuff.GenesisHash() {
		t.Errorf("round-tripped genesis hashes to %x, want %x", got.Hash(), hotstuff.GenesisHash())
	}
	if got.Proposer() != 0 || got.View() != 0 {
		t.Errorf("round-tripped genesis = {View:%d Proposer:%d}, want both 0", got.View(), got.Proposer())
	}
}

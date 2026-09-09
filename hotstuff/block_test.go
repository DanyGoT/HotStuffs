package hotstuff

import (
	"bytes"
	"testing"
)

func TestGenesis(t *testing.T) {
	g := Genesis()
	if g.Parent() != (Hash{}) {
		t.Errorf("Parent() = %x, want zero", g.Parent())
	}
	if g.View() != 0 {
		t.Errorf("View() = %d, want 0", g.View())
	}
	if g.Proposer() != 0 {
		t.Errorf("Proposer() = %d, want 0", g.Proposer())
	}
	if qc := g.QC(); qc.View != 0 || qc.BlockHash != (Hash{}) || len(qc.Sigs) != 0 {
		t.Errorf("QC() = %+v, want zero value", qc)
	}
	if len(g.Cmds()) != 0 {
		t.Errorf("Cmds() = %v, want none", g.Cmds())
	}

	if Genesis() != g {
		t.Error("Genesis() returned a different pointer on a second call; it must be an immutable singleton")
	}

	if GenesisHash() != g.Hash() {
		t.Errorf("GenesisHash() = %x, want Genesis().Hash() = %x", GenesisHash(), g.Hash())
	}
}

func TestBlockAccessors(t *testing.T) {
	parent := Hash{}
	for i := range parent {
		parent[i] = 0x42
	}
	qcHash := Hash{}
	for i := range qcHash {
		qcHash[i] = 0x99
	}
	qc := QuorumCert{View: 3, BlockHash: qcHash, Sigs: []Signature{{Signer: 1, Data: []byte("s")}}}
	cmds := [][]byte{[]byte("a"), []byte("bc")}

	b := NewBlock(parent, 5, ID(2), qc, cmds)

	if b.Parent() != parent {
		t.Errorf("Parent() = %x, want %x", b.Parent(), parent)
	}
	if b.View() != 5 {
		t.Errorf("View() = %d, want 5", b.View())
	}
	if b.Proposer() != 2 {
		t.Errorf("Proposer() = %d, want 2", b.Proposer())
	}
	if got := b.QC(); got.View != qc.View || got.BlockHash != qc.BlockHash || len(got.Sigs) != len(qc.Sigs) {
		t.Errorf("QC() = %+v, want %+v", got, qc)
	}
	gotCmds := b.Cmds()
	if len(gotCmds) != len(cmds) {
		t.Fatalf("Cmds() has %d entries, want %d", len(gotCmds), len(cmds))
	}
	for i := range cmds {
		if !bytes.Equal(gotCmds[i], cmds[i]) {
			t.Errorf("Cmds()[%d] = %q, want %q", i, gotCmds[i], cmds[i])
		}
	}
	if b.Hash() != blockDigest(parent, 5, 2, qc, cmds) {
		t.Errorf("Hash() does not match blockDigest of the same fields")
	}
}

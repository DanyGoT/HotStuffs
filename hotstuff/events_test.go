package hotstuff

import (
	"bytes"
	"testing"
)

// sigEqual compares signatures field-by-field: Signature holds a []byte,
// which makes it non-comparable with ==.
func sigEqual(a, b Signature) bool {
	return a.Signer == b.Signer && bytes.Equal(a.Data, b.Data)
}

// TestEventSetIsClosed dispatches one value of every Event type through a
// switch with no default case. This is compile-time documentation of the
// closed set: an event type added to the slice below but missing from the
// switch fails this test instead of silently falling through.
func TestEventSetIsClosed(t *testing.T) {
	events := []Event{
		ProposeEvent{},
		VoteEvent{},
		TimeoutEvent{},
		FetchedEvent{},
		ViewTimeoutEvent{},
	}
	hit := make([]bool, len(events))
	for i, e := range events {
		switch e.(type) {
		case ProposeEvent:
			hit[i] = true
		case VoteEvent:
			hit[i] = true
		case TimeoutEvent:
			hit[i] = true
		case FetchedEvent:
			hit[i] = true
		case ViewTimeoutEvent:
			hit[i] = true
		}
	}
	for i, ok := range hit {
		if !ok {
			t.Errorf("event %d (%T) hit no switch arm", i, events[i])
		}
	}
}

// TestEmbeddedFieldsPromoted is a compile-level check that the core relies on:
// it fails to build if any of these promoted accesses stop working.
func TestEmbeddedFieldsPromoted(t *testing.T) {
	blk := Genesis()
	sig := Signature{Signer: 1, Data: []byte("s")}
	tc := &TimeoutCert{View: 2}

	pe := ProposeEvent{Proposal{Block: blk, Sig: sig, TC: tc}}
	if pe.Block != blk {
		t.Errorf("ProposeEvent.Block = %v, want %v", pe.Block, blk)
	}
	if !sigEqual(pe.Sig, sig) {
		t.Errorf("ProposeEvent.Sig = %+v, want %+v", pe.Sig, sig)
	}
	if pe.TC != tc {
		t.Errorf("ProposeEvent.TC = %v, want %v", pe.TC, tc)
	}

	ve := VoteEvent{PartialCert{View: 3, BlockHash: GenesisHash(), Sig: sig}}
	if ve.View != 3 {
		t.Errorf("VoteEvent.View = %d, want 3", ve.View)
	}
	if ve.BlockHash != GenesisHash() {
		t.Errorf("VoteEvent.BlockHash = %x, want %x", ve.BlockHash, GenesisHash())
	}
	if !sigEqual(ve.Sig, sig) {
		t.Errorf("VoteEvent.Sig = %+v, want %+v", ve.Sig, sig)
	}

	qc := QuorumCert{View: 4}
	te := TimeoutEvent{TimeoutMsg{View: 5, Sig: sig, HighQC: qc}}
	if te.View != 5 {
		t.Errorf("TimeoutEvent.View = %d, want 5", te.View)
	}
	if te.HighQC.View != qc.View || te.HighQC.BlockHash != qc.BlockHash || len(te.HighQC.Sigs) != len(qc.Sigs) {
		t.Errorf("TimeoutEvent.HighQC = %+v, want %+v", te.HighQC, qc)
	}
}

// TestQueueFIFO keeps to a single goroutine: it fills the queue to capacity
// (Push must not block for that), then drains it and checks order.
func TestQueueFIFO(t *testing.T) {
	const n = 4
	q := NewQueue(n)
	for i := range n {
		q.Push(ViewTimeoutEvent{View: View(i)})
	}
	for i := range n {
		e := <-q
		vt, ok := e.(ViewTimeoutEvent)
		if !ok {
			t.Fatalf("event %d has type %T, want ViewTimeoutEvent", i, e)
		}
		if vt.View != View(i) {
			t.Errorf("event %d: View = %d, want %d", i, vt.View, i)
		}
	}
}

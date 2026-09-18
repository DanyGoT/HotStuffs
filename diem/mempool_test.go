package diem

import "testing"

func TestFIFOPoolAddReturnsFalseWhenFull(t *testing.T) {
	p := NewFIFOPool(2, 10)
	if !p.Add([]byte("a")) {
		t.Fatal("Add failed on an empty pool")
	}
	if !p.Add([]byte("b")) {
		t.Fatal("Add failed at capacity-1")
	}
	if p.Add([]byte("c")) {
		t.Fatal("Add succeeded past capacity, want false")
	}
}

func TestFIFOPoolGetTransactionsFIFOOrderAndBatchLimit(t *testing.T) {
	p := NewFIFOPool(10, 3)
	txns := [][]byte{{1}, {2}, {3}, {4}, {5}}
	for _, txn := range txns {
		if !p.Add(txn) {
			t.Fatalf("Add(%v) failed", txn)
		}
	}

	first := p.GetTransactions()
	if len(first) != 3 {
		t.Fatalf("first batch has %d txns, want 3 (the batch limit)", len(first))
	}
	for i, txn := range first {
		if txn[0] != txns[i][0] {
			t.Fatalf("first batch[%d] = %v, want %v (FIFO order)", i, txn, txns[i])
		}
	}

	second := p.GetTransactions()
	if len(second) != 2 {
		t.Fatalf("second batch has %d txns, want 2 (the remainder)", len(second))
	}
	for i, txn := range second {
		if txn[0] != txns[3+i][0] {
			t.Fatalf("second batch[%d] = %v, want %v (FIFO order)", i, txn, txns[3+i])
		}
	}
}

func TestFIFOPoolGetTransactionsOnEmptyPoolReturnsEmptySlice(t *testing.T) {
	p := NewFIFOPool(10, 3)
	got := p.GetTransactions()
	if got == nil {
		t.Fatal("GetTransactions returned nil on an empty pool, want an empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("GetTransactions returned %d txns from an empty pool, want 0", len(got))
	}
}

package diem

// FIFOPool is the paper's MemPool module (3.6) over a bounded FIFO.
//
// Transactions are pulled, not pushed: a flood fills the buffer and is dropped
// at the edge rather than starving the protocol messages behind it, and no
// priority logic is needed anywhere in the core.
type FIFOPool struct {
	q     chan []byte
	batch int
}

// NewFIFOPool returns a pool buffering capacity transactions and handing out
// at most batch of them per proposal.
func NewFIFOPool(capacity, batch int) *FIFOPool {
	return &FIFOPool{q: make(chan []byte, capacity), batch: batch}
}

// Add offers a transaction, reporting false when the buffer is full. It never
// blocks: a client is told to retry rather than the replica stalling.
func (p *FIFOPool) Add(txn []byte) bool {
	select {
	case p.q <- txn:
		return true
	default:
		return false
	}
}

// GetTransactions takes up to batch transactions. An empty result is normal
// and still produces a block: the pipeline is what commits the blocks below
// it, so an idle round still has work to do.
func (p *FIFOPool) GetTransactions() [][]byte {
	out := make([][]byte, 0, p.batch)
	for len(out) < p.batch {
		select {
		case txn := <-p.q:
			out = append(out, txn)
		default:
			return out
		}
	}
	return out
}

var _ MemPool = (*FIFOPool)(nil)

package hotstuff

import "sync"

// MemLog is the default Executor: committed blocks in commit order. Its mutex
// guards application state, not protocol state, which is why it is the only
// lock in this package.
type MemLog struct {
	mu     sync.Mutex
	blocks []*Block
}

func NewMemLog() *MemLog { return &MemLog{} }

func (l *MemLog) Exec(b *Block) {
	l.mu.Lock()
	l.blocks = append(l.blocks, b)
	l.mu.Unlock()
}

// Snapshot copies the committed log.
func (l *MemLog) Snapshot() []*Block {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*Block(nil), l.blocks...)
}

func (l *MemLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.blocks)
}

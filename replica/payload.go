package replica

import "time"

// Payload is a synthetic workload: batches of identical commands of a fixed
// size, capped at a target rate. Transactions is called only from the
// consensus goroutine, so it needs no lock, and it never blocks — it returns
// nothing when this instant's budget is spent.
type Payload struct {
	cmd    []byte
	batch  int
	rate   float64 // commands per second; 0 means unthrottled
	last   time.Time
	credit float64
}

// NewPayload returns a command source of size-byte commands, at most batch per
// proposal and at most rate per second. A rate of 0 is unthrottled.
func NewPayload(size, batch, rate int) *Payload {
	if size < 1 {
		size = 1
	}
	if batch < 1 {
		batch = 1
	}
	return &Payload{cmd: make([]byte, size), batch: batch, rate: float64(rate)}
}

// Transactions is the paper's MemPool.get_transactions (3.6).
func (p *Payload) Transactions() [][]byte {
	n := p.batch
	if p.rate > 0 {
		now := time.Now()
		if !p.last.IsZero() {
			p.credit = min(p.credit+now.Sub(p.last).Seconds()*p.rate, p.rate)
		}
		p.last = now
		if n = min(p.batch, int(p.credit)); n == 0 {
			return nil
		}
		p.credit -= float64(n)
	}
	cmds := make([][]byte, n)
	for i := range cmds {
		cmds[i] = p.cmd // read-only and only ever hashed, so one buffer will do
	}
	return cmds
}

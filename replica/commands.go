package replica

import (
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// NoCommands proposes nothing. A view still gets a block, which is all the
// pipeline needs to keep committing.
type NoCommands struct{}

func (NoCommands) Poll() ([][]byte, bool) { return nil, false }

// Payload is a synthetic workload: batches of identical commands of a fixed
// size, capped at a target rate. Poll is called only from the consensus
// goroutine, so it needs no lock, and it never blocks — it returns nothing when
// this instant's budget is spent.
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

func (p *Payload) Poll() ([][]byte, bool) {
	n := p.batch
	if p.rate > 0 {
		now := time.Now()
		if !p.last.IsZero() {
			p.credit = min(p.credit+now.Sub(p.last).Seconds()*p.rate, p.rate)
		}
		p.last = now
		if n = min(p.batch, int(p.credit)); n == 0 {
			return nil, false
		}
		p.credit -= float64(n)
	}
	cmds := make([][]byte, n)
	for i := range cmds {
		cmds[i] = p.cmd // read-only and only ever hashed, so one buffer will do
	}
	return cmds, true
}

var (
	_ hotstuff.CommandQueue = NoCommands{}
	_ hotstuff.CommandQueue = (*Payload)(nil)
)

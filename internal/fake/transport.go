// Package fake holds test doubles for the seams in hotstuff: a transport that
// records instead of sending, a hand-driven clock, and a scripted command
// queue.
package fake

import "github.com/DanyGoT/HotStuffs/hotstuff"

// Transport records outbound messages instead of sending them.
type Transport struct {
	Proposals []hotstuff.Proposal
	Votes     []hotstuff.PartialCert
	Timeouts  []hotstuff.TimeoutMsg
	Fetches   []hotstuff.Hash
}

func (t *Transport) Propose(p hotstuff.Proposal) { t.Proposals = append(t.Proposals, p) }

func (t *Transport) Vote(cert hotstuff.PartialCert) {
	t.Votes = append(t.Votes, cert)
}

func (t *Transport) Timeout(m hotstuff.TimeoutMsg) { t.Timeouts = append(t.Timeouts, m) }

func (t *Transport) Fetch(h hotstuff.Hash) { t.Fetches = append(t.Fetches, h) }

// Commands hands out one scripted batch per Poll, then reports empty.
type Commands struct{ Batches [][][]byte }

func (c *Commands) Poll() ([][]byte, bool) {
	if len(c.Batches) == 0 {
		return nil, false
	}
	b := c.Batches[0]
	c.Batches = c.Batches[1:]
	return b, true
}

var (
	_ hotstuff.Transport    = (*Transport)(nil)
	_ hotstuff.CommandQueue = (*Commands)(nil)
)

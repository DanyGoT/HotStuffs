package consensus

import (
	"time"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// NewViewDuration returns a view timer policy starting at base.
func NewViewDuration(base, max time.Duration, factor float64) *hotstuff.Duration {
	return hotstuff.NewDuration(base, max, factor)
}

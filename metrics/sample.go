package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Sample writes one NDJSON line per interval to w until ctx is done, and one
// final line on the way out so a short run still produces data.
func (m *Metrics) Sample(ctx context.Context, w io.Writer, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("metrics: Sample interval must be positive")
	}

	enc := json.NewEncoder(w)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := enc.Encode(m.Snapshot()); err != nil {
				return err
			}
		case <-ctx.Done():
			if err := enc.Encode(m.Snapshot()); err != nil {
				return err
			}
			return ctx.Err()
		}
	}
}

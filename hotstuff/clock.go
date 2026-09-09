package hotstuff

import "time"

// SystemClock is the wall-clock Clock. time.AfterFunc runs its callback on its
// own goroutine, which is why a timer callback may only enqueue an event.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

var _ Clock = SystemClock{}

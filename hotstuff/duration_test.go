package hotstuff

import (
	"testing"
	"time"
)

func TestDurationGrowsThenResets(t *testing.T) {
	base, max, factor := 10*time.Millisecond, 80*time.Millisecond, 2.0
	d := NewDuration(base, max, factor)

	if got := d.Duration(); got != base {
		t.Fatalf("Duration() = %v, want base %v", got, base)
	}

	d.ViewStarted()
	if got := d.Duration(); got != base {
		t.Errorf("ViewStarted() changed Duration(): got %v, want %v", got, base)
	}

	want := base
	for i := range 5 {
		d.ViewTimedOut()
		want = min(time.Duration(float64(want)*factor), max)
		if got := d.Duration(); got != want {
			t.Fatalf("after %d timeouts, Duration() = %v, want %v", i+1, got, want)
		}
	}
	if got := d.Duration(); got != max {
		t.Errorf("Duration() = %v, want saturated at max %v", got, max)
	}

	d.ViewSucceeded()
	if got := d.Duration(); got != base {
		t.Errorf("Duration() after ViewSucceeded() = %v, want base %v", got, base)
	}
}

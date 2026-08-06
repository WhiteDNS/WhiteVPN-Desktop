package session

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestForEachBoundedLimitsRunningWorkers(t *testing.T) {
	var active, maximum atomic.Int32
	forEachBounded(context.Background(), []string{"a", "b", "c", "d", "e"}, 2, func(string) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
	})
	if maximum.Load() > 2 {
		t.Fatalf("ran %d workers with a limit of 2", maximum.Load())
	}
}

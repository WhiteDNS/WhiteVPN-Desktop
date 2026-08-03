package traffic

import (
	"testing"
	"time"
)

func TestMeterUsesFirstSampleAsBaseline(t *testing.T) {
	var meter Meter
	start := time.Unix(100, 0)

	first := meter.Observe(Counters{RXBytes: 1000, TXBytes: 500}, start)
	if first != (Usage{}) {
		t.Fatalf("expected first sample to establish baseline, got %#v", first)
	}

	next := meter.Observe(Counters{RXBytes: 2500, TXBytes: 1500}, start.Add(2*time.Second))
	if next.RXBytes != 1500 || next.TXBytes != 1000 || next.TotalBytes != 2500 {
		t.Fatalf("unexpected cumulative usage: %#v", next)
	}
	if next.RXBytesPerSecond != 750 || next.TXBytesPerSecond != 500 {
		t.Fatalf("unexpected speeds: %#v", next)
	}
}

func TestMeterResetsWhenCountersMoveBackwards(t *testing.T) {
	var meter Meter
	start := time.Unix(100, 0)
	_ = meter.Observe(Counters{RXBytes: 1000, TXBytes: 1000}, start)
	_ = meter.Observe(Counters{RXBytes: 1500, TXBytes: 1200}, start.Add(time.Second))

	reset := meter.Observe(Counters{RXBytes: 100, TXBytes: 100}, start.Add(2*time.Second))
	if reset != (Usage{}) {
		t.Fatalf("expected counter reset to become a new baseline, got %#v", reset)
	}

	next := meter.Observe(Counters{RXBytes: 300, TXBytes: 250}, start.Add(3*time.Second))
	if next.RXBytes != 200 || next.TXBytes != 150 {
		t.Fatalf("unexpected usage after reset: %#v", next)
	}
}

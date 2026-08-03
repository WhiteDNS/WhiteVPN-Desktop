package traffic

import (
	"context"
	"errors"
	"time"
)

var ErrNoSample = errors.New("traffic sample not available yet")

type Counters struct {
	RXBytes int64
	TXBytes int64
}

type Usage struct {
	RXBytes          int64
	TXBytes          int64
	RXBytesPerSecond int64
	TXBytesPerSecond int64
	TotalBytes       int64
}

type Sampler interface {
	Sample(ctx context.Context, pid int) (Counters, error)
}

type SamplerFunc func(context.Context, int) (Counters, error)

func (f SamplerFunc) Sample(ctx context.Context, pid int) (Counters, error) {
	return f(ctx, pid)
}

type Meter struct {
	baseline    Counters
	last        Counters
	lastAt      time.Time
	hasBaseline bool
	hasLast     bool
}

func (m *Meter) Observe(sample Counters, now time.Time) Usage {
	if !m.hasBaseline || sample.RXBytes < m.baseline.RXBytes || sample.TXBytes < m.baseline.TXBytes {
		m.baseline = sample
		m.last = sample
		m.lastAt = now
		m.hasBaseline = true
		m.hasLast = true
		return Usage{}
	}

	usage := Usage{
		RXBytes:    maxInt64(0, sample.RXBytes-m.baseline.RXBytes),
		TXBytes:    maxInt64(0, sample.TXBytes-m.baseline.TXBytes),
		TotalBytes: maxInt64(0, sample.RXBytes-m.baseline.RXBytes) + maxInt64(0, sample.TXBytes-m.baseline.TXBytes),
	}

	if m.hasLast && !m.lastAt.IsZero() {
		elapsed := now.Sub(m.lastAt).Seconds()
		if elapsed > 0 {
			usage.RXBytesPerSecond = int64(float64(maxInt64(0, sample.RXBytes-m.last.RXBytes)) / elapsed)
			usage.TXBytesPerSecond = int64(float64(maxInt64(0, sample.TXBytes-m.last.TXBytes)) / elapsed)
		}
	}

	m.last = sample
	m.lastAt = now
	m.hasLast = true
	return usage
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

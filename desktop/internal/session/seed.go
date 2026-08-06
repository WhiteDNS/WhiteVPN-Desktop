package session

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

// Seeding gives the engine's automatic group real measurements to choose from
// before it has to choose.
//
// A url-test group picks the lowest measured delay among the nodes that
// answered. Until it has measured, every node looks identical to it and
// mihomo's `fast()` returns the first proxy in the group — so a group handed
// eight hundred unmeasured nodes behaves exactly like the head-of-the-catalogue
// walk this was meant to replace, only inside the engine where it cannot be
// seen.
//
// And it stays that way for a while. The engine's own health check runs ten
// nodes at a time (`errgroup.SetLimit(10)` in the provider's healthcheck), so a
// first full round over eight hundred nodes is minutes, not seconds.
//
// So the app measures a sample itself, first, through the same engine and
// against the same URL the group tests with — which puts the results in the very
// history `fast()` reads. By the time the group is selected it has real numbers
// for a spread of the catalogue and picks the best of them.
const (
	// How many nodes are measured. Enough to be very unlikely to draw an
	// all-dead sample — at the observed 18% failure rate, thirty-two nodes miss
	// entirely about once in every 10^25 connects — and small enough to finish
	// in seconds.
	seedSample = 32

	// How many at once. The engine handles these as ordinary delay tests, and
	// they are cheap; the limit is about not opening thirty-two connections on a
	// phone-tethered link at once.
	seedConcurrency = 12

	// How long one node is given to answer, and the whole sample.
	seedProbeTimeout = 4 * time.Second
	seedBudget       = 12 * time.Second

	// How many nodes have to answer before the group is worth selecting. The
	// rest keep measuring in the background: waiting for all thirty-two when
	// five have already answered adds seconds to every connect on a good
	// network, for a choice between nodes that are all working.
	seedEnough = 5
)

// delayTester is the part of the engine seeding needs.
type delayTester interface {
	TestDelayMS(ctx context.Context, proxy, testURL string, timeoutMS int) (int, error)
}

// sampleForSeeding picks which nodes to measure.
//
// The sample is random, and that is the point rather than an implementation
// detail. Every user taking the same nodes in the same order is what turned a
// bad head of the catalogue into "the app cannot connect" for everybody at once;
// a random draw per connect means a node that is down costs one user one
// measurement instead of costing every user their connection.
func sampleForSeeding(candidates []string, size int) []string {
	if len(candidates) <= size {
		sample := make([]string, len(candidates))
		copy(sample, candidates)
		return sample
	}
	shuffled := make([]string, len(candidates))
	copy(shuffled, candidates)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:size]
}

// seedMeasurements measures a sample of the catalogue and returns once enough
// nodes have answered, leaving the rest to finish in the background.
//
// The count returned is how many had answered at that moment. Zero is not a
// failure to act on by itself — the sample may simply be slower than the budget,
// and the group is still the right thing to select — but it is worth knowing.
func (s *Session) seedMeasurements(ctx context.Context, candidates []string) int {
	if s.process == nil {
		return 0
	}
	return seedMeasurements(ctx, s.process, candidates)
}

func seedMeasurements(ctx context.Context, engine delayTester, candidates []string) int {
	if len(candidates) == 0 {
		return 0
	}

	// Deliberately not deferred: this returns as soon as enough nodes have
	// answered, and the rest of the sample goes on measuring behind it. Cancelling
	// the budget here would stop exactly the work that makes the group's next
	// choice a better one. It is still tied to ctx, so a user who cancels the
	// connect stops this with it.
	budget, cancelBudget := context.WithTimeout(ctx, seedBudget)

	sample := sampleForSeeding(candidates, seedSample)

	var (
		mu        sync.Mutex
		answered  int
		enough    = make(chan struct{})
		signalled bool
	)
	done := make(chan struct{})
	go func() {
		<-done
		cancelBudget()
	}()

	go func() {
		defer close(done)
		forEachBounded(budget, sample, seedConcurrency, func(name string) {
			// The result is not read: it goes into the engine's own history for
			// this node, which is where the group looks. This call is made for
			// its side effect.
			if _, err := engine.TestDelayMS(budget, name, mihomoconf.DelayTestURL, int(seedProbeTimeout/time.Millisecond)); err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			answered++
			if answered >= seedEnough && !signalled {
				signalled = true
				close(enough)
			}
		})
	}()

	select {
	case <-enough:
	case <-done:
	case <-budget.Done():
	}

	mu.Lock()
	defer mu.Unlock()
	return answered
}

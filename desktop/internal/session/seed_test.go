package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeDelayTester struct {
	mu      sync.Mutex
	asked   []string
	fail    func(name string) bool
	latency time.Duration
}

func (f *fakeDelayTester) TestDelayMS(ctx context.Context, proxy, _ string, _ int) (int, error) {
	if f.latency > 0 {
		select {
		case <-time.After(f.latency):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	f.mu.Lock()
	f.asked = append(f.asked, proxy)
	f.mu.Unlock()

	if f.fail != nil && f.fail(proxy) {
		return 0, errors.New("no answer")
	}
	return 120, nil
}

func (f *fakeDelayTester) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.asked))
	copy(out, f.asked)
	return out
}

func names(prefix string, count int) []string {
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, prefix+string(rune('A'+i%26))+strings.Repeat("!", i/26))
	}
	return out
}

// Every user drawing the same nodes in the same order is what turned a bad head
// of the catalogue into "the app cannot connect" for everybody at once.
func TestSampleForSeedingDoesNotAlwaysDrawTheSameNodes(t *testing.T) {
	candidates := names("node", 200)

	first := strings.Join(sampleForSeeding(candidates, seedSample), ",")
	differed := false
	for i := 0; i < 20 && !differed; i++ {
		if strings.Join(sampleForSeeding(candidates, seedSample), ",") != first {
			differed = true
		}
	}
	if !differed {
		t.Fatal("twenty draws produced the same sample; the catalogue is being walked, not sampled")
	}
}

func TestSampleForSeedingTakesEverythingWhenTheCatalogueIsSmall(t *testing.T) {
	candidates := []string{"one", "two"}
	sample := sampleForSeeding(candidates, seedSample)
	if len(sample) != 2 {
		t.Fatalf("expected both nodes, got %v", sample)
	}
	sample[0] = "changed"
	if candidates[0] != "one" {
		t.Fatal("the caller's slice was handed out rather than copied")
	}
}

func TestSampleForSeedingIsCapped(t *testing.T) {
	if size := len(sampleForSeeding(names("node", 800), seedSample)); size != seedSample {
		t.Fatalf("expected %d nodes measured, got %d", seedSample, size)
	}
}

// Waiting for all thirty-two when five have answered adds seconds to every
// connect on a good network, for a choice between nodes that are all working.
func TestSeedingReturnsOnceEnoughNodesAnswer(t *testing.T) {
	engine := &fakeDelayTester{latency: 150 * time.Millisecond}

	start := time.Now()
	answered := seedMeasurements(context.Background(), engine, names("node", 800))
	elapsed := time.Since(start)

	if answered < seedEnough {
		t.Fatalf("expected at least %d answers, got %d", seedEnough, answered)
	}
	if elapsed > seedBudget {
		t.Fatalf("seeding took %s, past its %s budget", elapsed, seedBudget)
	}
	if measured := len(engine.seen()); measured > seedSample {
		t.Fatalf("measured %d nodes, more than the %d sampled", measured, seedSample)
	}
}

// A sample where nothing answers must still end, and end honestly, rather than
// hanging a connect that could have fallen through to the node walk.
func TestSeedingGivesUpWhenNothingAnswers(t *testing.T) {
	engine := &fakeDelayTester{fail: func(string) bool { return true }}

	start := time.Now()
	if answered := seedMeasurements(context.Background(), engine, names("node", 60)); answered != 0 {
		t.Fatalf("expected no answers, got %d", answered)
	}
	if elapsed := time.Since(start); elapsed > seedBudget {
		t.Fatalf("seeding took %s, past its %s budget", elapsed, seedBudget)
	}
}

func TestSeedingStopsWhenTheConnectIsCancelled(t *testing.T) {
	engine := &fakeDelayTester{latency: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if answered := seedMeasurements(ctx, engine, names("node", 60)); answered != 0 {
		t.Fatalf("a cancelled connect should measure nothing, got %d", answered)
	}
}

func TestSeedingWithNothingToMeasure(t *testing.T) {
	if answered := seedMeasurements(context.Background(), &fakeDelayTester{}, nil); answered != 0 {
		t.Fatalf("expected nothing, got %d", answered)
	}
}

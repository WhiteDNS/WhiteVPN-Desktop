package model

import "testing"

func TestNormalizeNodeTestRequestRepairsWhatCannotWork(t *testing.T) {
	// A run with no test selected would look like a run that found nothing.
	got := NormalizeNodeTestRequest(NodeTestRequest{Nodes: []string{"a", "", "a", "b"}})
	if !got.Reachability {
		t.Fatal("expected a request with no test to fall back to reachability")
	}
	if len(got.Nodes) != 2 {
		t.Fatalf("expected duplicates and blanks to be dropped, got %#v", got.Nodes)
	}

	// Out of range is replaced with the default rather than clamped, as the
	// settings do it: a value nobody chose beats one bent into shape.
	wild := NormalizeNodeTestRequest(NodeTestRequest{
		Nodes: []string{"a"}, Delay: true,
		DelayTimeoutMs: 9_000_000, DelayWorkers: 0,
		ReachabilityTimeoutMs: -1, SpeedBudgetMs: 1,
	})
	if wild.DelayTimeoutMs != 5000 || wild.DelayWorkers != 16 {
		t.Fatalf("delay bounds not applied: %#v", wild)
	}
	if wild.ReachabilityTimeoutMs != 3500 || wild.SpeedBudgetMs != 8000 {
		t.Fatalf("other bounds not applied: %#v", wild)
	}
	if wild.Reachability {
		t.Fatal("a request that named a test must not gain another")
	}
	if wild.DelayTimeout().Milliseconds() != 5000 {
		t.Fatalf("derived duration disagrees: %v", wild.DelayTimeout())
	}
}

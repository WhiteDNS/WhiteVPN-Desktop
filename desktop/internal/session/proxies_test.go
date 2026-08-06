package session

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type fakeProxyReader struct {
	payload string
	err     error
}

func (f fakeProxyReader) Proxies(context.Context) (json.RawMessage, error) {
	if f.err != nil {
		return nil, f.err
	}
	return json.RawMessage(f.payload), nil
}

// The interface has to name a place, not a group. Asking the engine what the
// group settled on is the only way to know, because the app no longer chooses.
func TestResolveGroupFollowsTheChain(t *testing.T) {
	proxies := map[string]proxyView{
		"WhiteDNS Proxy": {Type: "Selector", Now: "WhiteDNS Auto"},
		"WhiteDNS Auto":  {Type: "URLTest", Now: "Germany 3"},
		"Germany 3":      {Type: "Vless"},
	}
	if name := resolveGroup(proxies, "WhiteDNS Proxy"); name != "Germany 3" {
		t.Fatalf("expected the node behind both groups, got %q", name)
	}
}

// A group pointing at itself, or at each other, must not spin.
func TestResolveGroupSurvivesALoop(t *testing.T) {
	proxies := map[string]proxyView{
		"A": {Now: "B"},
		"B": {Now: "A"},
	}
	if name := resolveGroup(proxies, "A"); name == "" {
		t.Fatal("expected a name rather than nothing")
	}
}

func TestProxySnapshotReadsTheEnginesView(t *testing.T) {
	reader := fakeProxyReader{payload: `{"proxies":{"Germany 3":{"type":"Vless","history":[{"delay":180}]}}}`}
	proxies, err := proxySnapshot(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if delay := lastDelay(proxies, "Germany 3"); delay != 180 {
		t.Fatalf("expected the last measurement, got %d", delay)
	}
	if _, err := proxySnapshot(context.Background(), fakeProxyReader{err: errors.New("no")}); err == nil {
		t.Fatal("expected the engine's failure to surface")
	}
}

// A zero delay is a failed measurement, not an instant one. Sorting it first
// would put the nodes that answered nothing at the front of the queue.
func TestLastDelayTreatsZeroAsUnknown(t *testing.T) {
	proxies := map[string]proxyView{
		"failed":    {History: []delayHistory{{Delay: 120}, {Delay: 0}}},
		"never run": {},
	}
	if delay := lastDelay(proxies, "failed"); delay != noDelay {
		t.Fatalf("a failed measurement should not sort as fast, got %d", delay)
	}
	if delay := lastDelay(proxies, "never run"); delay != noDelay {
		t.Fatalf("an unmeasured node should sort last, got %d", delay)
	}
	if delay := lastDelay(proxies, "absent"); delay != noDelay {
		t.Fatalf("a node the engine does not hold should sort last, got %d", delay)
	}
}

// The fallback used to walk the catalogue from the top, so every user tried the
// same five nodes and Retry tried them again. With hundreds of nodes measured
// already, the order should come from the measurements.
func TestByMeasuredDelayPutsTheFastestFirst(t *testing.T) {
	candidates := []string{"slow", "dead", "fast", "unmeasured"}
	proxies := map[string]proxyView{
		"slow": {History: []delayHistory{{Delay: 900}}},
		"dead": {History: []delayHistory{{Delay: 0}}},
		"fast": {History: []delayHistory{{Delay: 90}}},
	}

	ordered := byMeasuredDelay(candidates, proxies)
	if ordered[0] != "fast" || ordered[1] != "slow" {
		t.Fatalf("expected fastest first, got %v", ordered)
	}
	// Nothing is known about either of the last two, so they keep the order they
	// arrived in rather than being shuffled arbitrarily.
	if ordered[2] != "dead" || ordered[3] != "unmeasured" {
		t.Fatalf("unmeasured nodes should keep their original order, got %v", ordered)
	}
	if len(ordered) != len(candidates) {
		t.Fatalf("ordering dropped nodes: %v", ordered)
	}
	if candidates[0] != "slow" {
		t.Fatal("the caller's slice should not be reordered in place")
	}
}

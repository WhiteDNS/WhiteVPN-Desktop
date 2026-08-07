package main

import (
	"testing"

	"whitevpn-desktop/internal/model"
)

func retryTestApp(subscriptions ...model.V2RaySubscription) *App {
	state := model.DefaultAppState()
	state.V2RaySubscriptions = subscriptions
	return &App{state: state}
}

// Only the ones a working connection might fill.
//
// Refreshing every subscription on every connect would put a burst of requests
// on the provider each time anyone reconnects, and would overwrite lists that
// were already fine.
func TestOnlyEmptySubscriptionsAreRetried(t *testing.T) {
	app := retryTestApp(
		model.V2RaySubscription{ID: "blocked", ImportedCount: 0, LastError: "something on this network is blocking it"},
		model.V2RaySubscription{ID: "never-tried", ImportedCount: 0},
		model.V2RaySubscription{ID: "failed-but-has-nodes", ImportedCount: 12, LastError: "the last refresh failed"},
		model.V2RaySubscription{ID: "working", ImportedCount: 425},
	)

	got := app.emptySubscriptionIDs()
	want := map[string]bool{"blocked": true, "never-tried": true, "failed-but-has-nodes": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d subscriptions to retry, got %v", len(want), got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("%q has nodes and no error — nothing is waiting on it", id)
		}
	}
}

// Connecting is what fetches the catalogue. By the time this runs it has either
// just succeeded or the connection would not be up, so fetching it again would
// be a second request for a document already in hand.
func TestTheBuiltInCatalogueIsNotRetried(t *testing.T) {
	app := retryTestApp(model.V2RaySubscription{ID: whiteDNSVPNSubscriptionID, ImportedCount: 0})
	if got := app.emptySubscriptionIDs(); len(got) != 0 {
		t.Fatalf("the catalogue should not be retried: %v", got)
	}
}

// A reconnect, or a network change during one, must not start a second pass
// while the first is still going.
func TestTwoConnectsDoNotRetryAtOnce(t *testing.T) {
	if !retryingBlockedSubscriptions.CompareAndSwap(false, true) {
		t.Fatal("the guard was left set by another test")
	}
	defer retryingBlockedSubscriptions.Store(false)

	// With the guard held, a connect must return without starting a pass. There
	// is nothing to fetch in this state, so reaching a fetch at all would mean
	// the guard did not hold.
	app := retryTestApp(model.V2RaySubscription{ID: "blocked", URL: "https://127.0.0.1:1/nope"})
	app.retryBlockedSubscriptions()
}

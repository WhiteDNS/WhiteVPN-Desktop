package main

import (
	"testing"

	"whitevpn-desktop/internal/model"
)

func appWithSources(subscriptions []string, manual bool) *App {
	state := model.DefaultAppState()
	state.V2RaySubscriptions = nil
	for _, id := range subscriptions {
		state.V2RaySubscriptions = append(state.V2RaySubscriptions, model.V2RaySubscription{ID: id})
	}
	state.V2RayProfiles = nil
	if manual {
		state.V2RayProfiles = []model.V2RayProfile{{ID: "p1"}}
	}
	return &App{state: state}
}

// Every list with nodes in it, including the one the user assembled by hand —
// leaving those out of "test everything" would leave out the nodes they care
// most about.
func TestEveryListIsCovered(t *testing.T) {
	got := appWithSources([]string{"whitedns-vpn", "mine"}, true).subscriptionIDsForTesting()
	want := []string{"whitedns-vpn", "mine", model.ManualServerSourceID}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

// A profile that belongs to a subscription is already covered by that
// subscription; only the hand-added ones are their own source.
func TestManualIsListedOnlyWhenThereAreHandAddedConfigs(t *testing.T) {
	app := appWithSources([]string{"whitedns-vpn"}, false)
	app.state.V2RayProfiles = []model.V2RayProfile{{ID: "p1", SubscriptionID: "whitedns-vpn"}}
	for _, id := range app.subscriptionIDsForTesting() {
		if id == model.ManualServerSourceID {
			t.Fatal("nothing was added by hand, so there is no manual list to test")
		}
	}
}

// The names on the page a run was started from do not describe the other lists,
// so a run covering everything names none — and must not be refused for it.
func TestARunCoveringEverythingNeedsNoNodeNames(t *testing.T) {
	app := appWithSources(nil, false)
	err := app.StartNodeTest(model.NodeTestRequest{AllSubscriptions: true, Reachability: true})
	if err != nil {
		t.Fatalf("a full run should be accepted without node names: %v", err)
	}
	app.CancelNodeTest()

	// And a single-subscription run with no names is still nothing to do.
	if err := app.StartNodeTest(model.NodeTestRequest{Reachability: true}); err == nil {
		t.Fatal("a run naming no nodes and no subscriptions should be refused")
	}
}

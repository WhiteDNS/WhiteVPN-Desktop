package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

// twoProviderApp gives the app two of the user's own subscriptions, each
// serving the links it is handed.
func twoProviderApp(t *testing.T, first, second string) *App {
	t.Helper()
	serve := func(body string) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(server.Close)
		return server.URL
	}

	dir := t.TempDir()
	app := &App{
		store:     profiles.NewStore(filepath.Join(dir, "state.json")),
		configDir: dir,
		state:     model.DefaultAppState(),
	}
	app.mu.Lock()
	app.state.V2RaySubscriptions = []model.V2RaySubscription{
		{ID: "one", Name: "Provider one", URL: serve(first)},
		{ID: "two", Name: "Provider two", URL: serve(second)},
	}
	_, _ = app.saveLocked()
	app.mu.Unlock()
	return app
}

func link(uuid, host, name string) string {
	return "vless://" + uuid + "@" + host + ":443?security=tls&type=tcp#" + name
}

// The point of All: one pool from every list.
func TestAllCombinesEverySubscription(t *testing.T) {
	app := twoProviderApp(t,
		link("11111111-1111-1111-1111-111111111111", "a.example.com", "Alpha"),
		link("22222222-2222-2222-2222-222222222222", "b.example.com", "Beta"))

	body, err := app.fetchSubscriptionBodyFor(context.Background(), model.AllSubscriptionsID)
	if err != nil {
		t.Fatal(err)
	}
	proxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected both providers' nodes, got %d: %#v", len(proxies), proxies)
	}
	names := proxies[0].Name() + " " + proxies[1].Name()
	for _, want := range []string{"Alpha", "Beta"} {
		if !strings.Contains(names, want) {
			t.Errorf("%q is missing from the merged list: %q", want, names)
		}
	}
}

// Providers name nodes for where they are, so "Germany 01" is in most lists.
// The engine keys proxies by name, so a repeat has to be told apart — and the
// qualifier is also the answer to "which list is this from".
func TestAllTellsApartNodesNamedTheSame(t *testing.T) {
	app := twoProviderApp(t,
		link("11111111-1111-1111-1111-111111111111", "a.example.com", "Germany%2001"),
		link("22222222-2222-2222-2222-222222222222", "b.example.com", "Germany%2001"))

	body, err := app.fetchSubscriptionBodyFor(context.Background(), model.AllSubscriptionsID)
	if err != nil {
		t.Fatal(err)
	}
	proxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected two nodes, got %d", len(proxies))
	}
	if proxies[0].Name() == proxies[1].Name() {
		t.Fatalf("both nodes kept the same name: %q", proxies[0].Name())
	}
	// The first keeps the plain name; only the one that needed telling apart
	// says where it came from.
	if proxies[0].Name() != "Germany 01" {
		t.Errorf("the first node should keep its own name, got %q", proxies[0].Name())
	}
	if !strings.Contains(proxies[1].Name(), "Provider two") {
		t.Errorf("the repeat should name its subscription, got %q", proxies[1].Name())
	}
}

// Providers resell each other. The same machine listed twice would be measured
// twice, shown twice, and picked between as though it were two.
func TestAllKeepsOneCopyOfAResoldServer(t *testing.T) {
	same := link("11111111-1111-1111-1111-111111111111", "shared.example.com", "Shared")
	app := twoProviderApp(t, same, same+"%20again")

	body, err := app.fetchSubscriptionBodyFor(context.Background(), model.AllSubscriptionsID)
	if err != nil {
		t.Fatal(err)
	}
	proxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("the same server survived twice: %#v", proxies)
	}
}

// One provider being down is the reason to have All, not a reason for it to
// fail.
func TestAllSurvivesAListThatCannotBeRead(t *testing.T) {
	app := twoProviderApp(t,
		link("11111111-1111-1111-1111-111111111111", "a.example.com", "Alpha"),
		"not a subscription at all")

	body, err := app.fetchSubscriptionBodyFor(context.Background(), model.AllSubscriptionsID)
	if err != nil {
		t.Fatal(err)
	}
	proxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || !strings.Contains(proxies[0].Name(), "Alpha") {
		t.Fatalf("expected the working list to carry the pool, got %#v", proxies)
	}
}

// Selectable, and it keeps its own filter like any other list.
func TestAllCanBeSelectedAndKeepsItsOwnChoice(t *testing.T) {
	app := twoProviderApp(t, link("11111111-1111-1111-1111-111111111111", "a.example.com", "Alpha"),
		link("22222222-2222-2222-2222-222222222222", "b.example.com", "Beta"))

	if _, err := app.SelectSubscription(model.AllSubscriptionsID); err != nil {
		t.Fatal(err)
	}
	if got := app.selectedSubscriptionID(); got != model.AllSubscriptionsID {
		t.Fatalf("selected %q", got)
	}
	setSelection(t, app, "DE", model.ConnectionSelection{})
	if _, err := app.SelectSubscription("one"); err != nil {
		t.Fatal(err)
	}
	state, err := app.SelectSubscription(model.AllSubscriptionsID)
	if err != nil {
		t.Fatal(err)
	}
	if state.WhiteVPN.CountryCode != "DE" {
		t.Fatalf("All did not keep its own filter: %+v", state.WhiteVPN)
	}
}

// A merged list is derived, so keeping a copy of it would freeze something that
// can disagree with the lists it was made from.
func TestAllIsNotStoredAsASnapshot(t *testing.T) {
	if subscriptionIsStorable(model.AllSubscriptionsID) {
		t.Fatal("a merged list must not be snapshotted")
	}
}

// The row is offered once somebody has a list of their own, and not before: a
// fresh install has two catalogues and no reason for a third row.
func TestTheAllRowAppearsOnlyWithAListOfTheirOwn(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.mu.Lock()
	app.ensureBuiltInCataloguesLocked()
	app.mu.Unlock()
	if _, ok := findV2RaySubscription(app.state, model.AllSubscriptionsID); ok {
		t.Fatalf("All was offered with only the built-in catalogues: %#v", app.state.V2RaySubscriptions)
	}

	app.mu.Lock()
	app.state.V2RaySubscriptions = append(app.state.V2RaySubscriptions,
		model.V2RaySubscription{ID: "mine", Name: "Mine", URL: "https://mine.example/sub"})
	app.ensureBuiltInCataloguesLocked()
	app.mu.Unlock()
	if _, ok := findV2RaySubscription(app.state, model.AllSubscriptionsID); !ok {
		t.Fatalf("All was not offered once a list was added: %#v", app.state.V2RaySubscriptions)
	}
	// Last, after the lists it is made of.
	if app.state.V2RaySubscriptions[len(app.state.V2RaySubscriptions)-1].ID != model.AllSubscriptionsID {
		t.Fatalf("All is not the last row: %#v", app.state.V2RaySubscriptions)
	}
}

// And it goes away again, taking the selection with it, when there is nothing
// left to combine.
func TestTheAllRowGoesAwayWithTheListThatEarnedIt(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.mu.Lock()
	app.state.V2RaySubscriptions = append(app.state.V2RaySubscriptions,
		model.V2RaySubscription{ID: "mine", Name: "Mine", URL: "https://mine.example/sub"})
	app.ensureBuiltInCataloguesLocked()
	app.state.SelectedSubscriptionID = model.AllSubscriptionsID

	app.state.V2RaySubscriptions = slices.DeleteFunc(app.state.V2RaySubscriptions,
		func(s model.V2RaySubscription) bool { return s.ID == "mine" })
	app.ensureBuiltInCataloguesLocked()
	app.mu.Unlock()

	if _, ok := findV2RaySubscription(app.state, model.AllSubscriptionsID); ok {
		t.Fatal("All outlived the list that earned it")
	}
	if model.IsEverySubscription(app.state.SelectedSubscriptionID) {
		t.Fatalf("the selection stayed on a row that is gone: %q", app.state.SelectedSubscriptionID)
	}
}

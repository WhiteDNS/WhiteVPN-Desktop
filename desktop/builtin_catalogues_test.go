package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

// Both catalogues are offered, private first, and neither is a build-time
// question: the private address is written into the binary, so a build made
// without any secrets still has one working list.
func TestBothCataloguesAreShippedWithTheApp(t *testing.T) {
	catalogues := builtInCatalogues()
	if len(catalogues) != len(model.BuiltInSubscriptionIDs) {
		t.Fatalf("expected one catalogue per id, got %#v", catalogues)
	}
	for i, id := range model.BuiltInSubscriptionIDs {
		if catalogues[i].id != id {
			t.Fatalf("catalogue %d is %q, want %q", i, catalogues[i].id, id)
		}
	}

	restore := whiteVPNPrivateSubscriptionURL
	defer func() { whiteVPNPrivateSubscriptionURL = restore }()

	// Nothing injected: a build made from a checkout alone has no private
	// catalogue, and must say so rather than pretending to one.
	whiteVPNPrivateSubscriptionURL = ""
	private, ok := builtInCatalogueFor(whiteVPNPrivateSubscriptionID)
	if !ok {
		t.Fatal("the private catalogue is not registered")
	}
	if private.available() {
		t.Fatal("a build with no injected address should have no private catalogue")
	}

	// An address and nothing else is enough, because the body is served in the
	// clear. A key here would be a key for something with no lock.
	whiteVPNPrivateSubscriptionURL = "https://private.invalid/list"
	private, _ = builtInCatalogueFor(whiteVPNPrivateSubscriptionID)
	if private.key != "" {
		t.Fatalf("the private list is served in the clear and must carry no key, got %q", private.key)
	}
	if !private.available() {
		t.Fatal("an injected address should be enough for the private catalogue")
	}
}

// The address must not be readable from a checkout. It has no key in front of
// it, so it is the whole of what protects the private server list.
func TestNoCatalogueAddressIsWrittenIntoTheSource(t *testing.T) {
	source, err := os.ReadFile("whitedns_vpn.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"https://gist.", "githubusercontent.com", "workers.dev"} {
		if strings.Contains(string(source), marker) {
			t.Errorf("a catalogue address is written into the source: %q", marker)
		}
	}
}

// The public one is ciphertext: an address without the passphrase yields bytes
// nobody can read, so half of it is not better than none.
func TestThePublicCatalogueNeedsBothHalves(t *testing.T) {
	restoreURL, restoreKey := whiteDNSVPNSubscriptionURL, whiteDNSVPNSubscriptionKey
	defer func() { whiteDNSVPNSubscriptionURL, whiteDNSVPNSubscriptionKey = restoreURL, restoreKey }()

	for _, testCase := range []struct {
		name string
		url  string
		key  string
		want bool
	}{
		{"both", "https://catalogue.invalid/encrypted", "passphrase", true},
		{"address only", "https://catalogue.invalid/encrypted", "", false},
		{"key only", "", "passphrase", false},
		{"neither", "", "", false},
	} {
		whiteDNSVPNSubscriptionURL, whiteDNSVPNSubscriptionKey = testCase.url, testCase.key
		public, _ := builtInCatalogueFor(whiteDNSVPNSubscriptionID)
		if got := public.available(); got != testCase.want {
			t.Errorf("%s: available = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// Both rows appear, in order, and a state file written before the private one
// existed gains it rather than staying on one list for ever.
func TestAStateFileFromBeforeGainsThePrivateRow(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.V2RaySubscriptions = []model.V2RaySubscription{
		{ID: whiteDNSVPNSubscriptionID, Name: "WhiteDNS VPN"},
	}

	app.mu.Lock()
	app.ensureBuiltInCataloguesLocked()
	app.mu.Unlock()

	listed := app.state.V2RaySubscriptions
	if len(listed) != 2 {
		t.Fatalf("expected both catalogues listed, got %#v", listed)
	}
	if _, ok := findV2RaySubscription(app.state, whiteVPNPrivateSubscriptionID); !ok {
		t.Fatalf("the private catalogue was not added: %#v", listed)
	}
	// And the old row is renamed rather than left saying what it used to.
	public, _ := findV2RaySubscription(app.state, whiteDNSVPNSubscriptionID)
	if public.Name != whiteDNSVPNSubscriptionName {
		t.Fatalf("the public row kept its old name: %q", public.Name)
	}
}

// Neither can be removed, and neither can be edited into pointing somewhere
// else — the app holds both addresses, so there is nothing an edit could change.
func TestNeitherCatalogueCanBeEditedOrRemoved(t *testing.T) {
	for _, id := range model.BuiltInSubscriptionIDs {
		app := testV2RaySubscriptionApp(t)
		app.mu.Lock()
		app.ensureBuiltInCataloguesLocked()
		_, _ = app.saveLocked()
		app.mu.Unlock()

		if _, err := app.SaveV2RaySubscription(model.V2RaySubscription{
			ID: id, Name: "Mine", URL: "https://evil.example",
		}); err == nil {
			t.Errorf("%s: expected editing to be refused", id)
		}
		if _, err := app.DeleteV2RaySubscription(id); err == nil {
			t.Errorf("%s: expected removal to be refused", id)
		}
		if _, ok := findV2RaySubscription(app.state, id); !ok {
			t.Errorf("%s: the row went missing", id)
		}
	}
}

// Neither address reaches the state, so neither is in a backup export or in
// anything the interface is handed.
func TestNoCatalogueAddressEntersState(t *testing.T) {
	// Stand-ins, because both are injected at link time and empty in a test
	// binary — and `strings.Contains(anything, "")` is true, so without them
	// this passes or fails for reasons that have nothing to do with what it
	// checks.
	restoreURL, restorePrivate := whiteDNSVPNSubscriptionURL, whiteVPNPrivateSubscriptionURL
	whiteDNSVPNSubscriptionURL = "https://catalogue.invalid/encrypted"
	whiteVPNPrivateSubscriptionURL = "https://private.invalid/list"
	defer func() {
		whiteDNSVPNSubscriptionURL, whiteVPNPrivateSubscriptionURL = restoreURL, restorePrivate
	}()

	app := &App{state: model.DefaultAppState()}
	app.mu.Lock()
	app.ensureBuiltInCataloguesLocked()
	app.mu.Unlock()

	raw, err := json.Marshal(app.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{whiteDNSVPNSubscriptionURL, whiteVPNPrivateSubscriptionURL} {
		if strings.Contains(string(raw), address) {
			t.Fatalf("a catalogue address reached the state: %s", address)
		}
	}
}

// Each keeps its own filter, its own cached nodes and its own last-updated
// stamp, because they are two different lists of servers.
func TestTheTwoCataloguesAreSeparateLists(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	app.mu.Lock()
	app.ensureBuiltInCataloguesLocked()
	_, _ = app.saveLocked()
	app.mu.Unlock()

	setSelection(t, app, "DE", model.ConnectionSelection{Types: []string{"anytls"}})
	if _, err := app.SelectSubscription(whiteDNSVPNSubscriptionID); err != nil {
		t.Fatal(err)
	}

	app.mu.Lock()
	settings := app.state.WhiteVPN
	app.mu.Unlock()
	if selectionIsNarrowed(settings) {
		t.Fatalf("the private list's filter followed the user onto the public one: %+v", settings)
	}
	if settings.SubscriptionSelections[whiteVPNPrivateSubscriptionID].CountryCode != "DE" {
		t.Fatalf("the private list did not keep its own filter: %+v", settings.SubscriptionSelections)
	}
}

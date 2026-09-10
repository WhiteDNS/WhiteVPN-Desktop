package main

import (
	"testing"

	"whitevpn-desktop/internal/model"
)

// setSelection is what the dashboard's two rows do, without going through the
// catalogue check SaveWhiteVPNSelection makes — these tests are about where the
// choice is kept, not about whether a node matches it.
func setSelection(t *testing.T, app *App, countryCode string, connection model.ConnectionSelection) {
	t.Helper()
	app.mu.Lock()
	app.state.WhiteVPN.CountryCode = countryCode
	app.state.WhiteVPN.Connection = connection
	_, err := app.saveLocked()
	app.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

// Issue #92: a subscription added by hand had no server that would connect.
// The filter chosen in the built-in catalogue followed the user onto their own
// list, matched none of its nodes, and the connect path refused all of them.
func TestAFilterFromAnotherListDoesNotRefuseEveryNode(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	mine := addTestSubscription(t, app, "Mine", "https://example.com/sub")
	setSelection(t, app, "DE", model.ConnectionSelection{Types: []string{"vless"}})

	if _, err := app.SelectSubscription(mine); err != nil {
		t.Fatal(err)
	}

	app.mu.Lock()
	settings := app.state.WhiteVPN
	app.mu.Unlock()
	if selectionIsNarrowed(settings) {
		t.Fatalf("the new list starts narrowed by a choice made in another: %+v", settings.Connection)
	}
	// Nodes named the way a private panel names them: no country in sight.
	nodes := []model.WhiteVPNNode{{Name: "Server-01", Type: "anytls"}, {Name: "Server-02", Type: "anytls"}}
	if names := preferredNodeNames(nodes, settings); len(names) != 0 {
		t.Fatalf("automatic should prefer nothing in particular, got %v", names)
	}
}

// Put aside, not thrown away. Somebody who filters the catalogue to Germany,
// looks at their own list and comes back should find Germany still chosen.
func TestEachListKeepsItsOwnChoice(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	mine := addTestSubscription(t, app, "Mine", "https://example.com/sub")

	setSelection(t, app, "DE", model.ConnectionSelection{Node: "Germany 01", Types: []string{"vless"}})
	if _, err := app.SelectSubscription(mine); err != nil {
		t.Fatal(err)
	}
	setSelection(t, app, "", model.ConnectionSelection{Types: []string{"anytls"}})

	back, err := app.SelectSubscription(whiteDNSVPNSubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if back.WhiteVPN.CountryCode != "DE" || back.WhiteVPN.Connection.Node != "Germany 01" {
		t.Fatalf("the catalogue's own choice did not come back: %+v", back.WhiteVPN)
	}

	forward, err := app.SelectSubscription(mine)
	if err != nil {
		t.Fatal(err)
	}
	if forward.WhiteVPN.CountryCode != "" || len(forward.WhiteVPN.Connection.Types) != 1 ||
		forward.WhiteVPN.Connection.Types[0] != "anytls" {
		t.Fatalf("the other list's choice did not come back: %+v", forward.WhiteVPN)
	}
}

// The selected subscription's choice lives in the two flat fields. A copy left
// in the store as well would give a later switch a stale answer to restore.
func TestTheSelectedListKeepsNoParkedCopy(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	mine := addTestSubscription(t, app, "Mine", "https://example.com/sub")
	setSelection(t, app, "DE", model.ConnectionSelection{})

	state, err := app.SelectSubscription(mine)
	if err != nil {
		t.Fatal(err)
	}
	if _, parked := state.WhiteVPN.SubscriptionSelections[mine]; parked {
		t.Fatalf("the selected list should hold no parked copy: %+v", state.WhiteVPN.SubscriptionSelections)
	}
	if state.WhiteVPN.SubscriptionSelections[whiteDNSVPNSubscriptionID].CountryCode != "DE" {
		t.Fatalf("the list left behind should have kept its choice: %+v", state.WhiteVPN.SubscriptionSelections)
	}
}

// The interface has no field for the parked choices, so a settings save from
// the page arrives with them empty. Taking the caller's word for it would wipe
// every other subscription's filter on the way past.
func TestASettingsSaveDoesNotWipeTheParkedChoices(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	mine := addTestSubscription(t, app, "Mine", "https://example.com/sub")
	setSelection(t, app, "DE", model.ConnectionSelection{})
	if _, err := app.SelectSubscription(mine); err != nil {
		t.Fatal(err)
	}

	app.mu.Lock()
	fromThePage := app.state.WhiteVPN
	app.mu.Unlock()
	fromThePage.SubscriptionSelections = nil
	fromThePage.Language = "fa"

	state, err := app.SaveWhiteVPNSettings(fromThePage)
	if err != nil {
		t.Fatal(err)
	}
	if state.WhiteVPN.SubscriptionSelections[whiteDNSVPNSubscriptionID].CountryCode != "DE" {
		t.Fatalf("a settings save wiped the parked choices: %+v", state.WhiteVPN.SubscriptionSelections)
	}
}

// A subscription that is gone should not keep a choice, and a list re-added
// under the same id should not come back wearing the old one's filter.
func TestDeletingASubscriptionForgetsItsChoice(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	mine := addTestSubscription(t, app, "Mine", "https://example.com/sub")
	if _, err := app.SelectSubscription(mine); err != nil {
		t.Fatal(err)
	}
	setSelection(t, app, "JP", model.ConnectionSelection{})
	if _, err := app.SelectSubscription(whiteDNSVPNSubscriptionID); err != nil {
		t.Fatal(err)
	}

	state, err := app.DeleteV2RaySubscription(mine)
	if err != nil {
		t.Fatal(err)
	}
	if _, parked := state.WhiteVPN.SubscriptionSelections[mine]; parked {
		t.Fatalf("a deleted subscription kept its choice: %+v", state.WhiteVPN.SubscriptionSelections)
	}
}

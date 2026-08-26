package main

import (
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

// The whole point of this reset is what it does not touch. Someone who narrowed
// the connection down while chasing a problem wants that undone; they do not
// want to lose the subscriptions they pasted in or the delays they measured.
func TestResettingSettingsKeepsEverythingThatIsNotASetting(t *testing.T) {
	app := newSettingsResetTestApp(t)

	app.state.V2RaySubscriptions = []model.V2RaySubscription{
		{ID: "provider", Name: "Provider", URL: "https://example.com/sub", ImportedCount: 12},
	}
	app.state.V2RayProfiles = []model.V2RayProfile{
		{ID: "manual-1", Name: "My own server"},
		{ID: "imported-1", Name: "Provider node", SubscriptionID: "provider"},
	}
	app.state.HiddenNodes = map[string][]string{"provider": {"A node they hid"}}

	// And the settings that should go.
	app.state.WhiteVPN.CountryCode = "NL"
	app.state.WhiteVPN.Connection = model.ConnectionSelection{Node: "one node only", Types: []string{"vless"}}
	app.state.WhiteVPN.DNSPrivacy = model.DNSPrivacySettings{Mode: model.DNSPrivacyDoH, DoHURL: "https://somewhere.example/dns"}
	app.state.WhiteVPN.KillSwitch = model.KillSwitchSettings{Enabled: true}
	app.state.WhiteVPN.ChainExitNode = "some exit"
	app.state.WhiteVPN.Language = "fa"
	app.state.Theme = "dark"

	state, err := app.ResetWhiteVPNSettings()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.V2RaySubscriptions) != 1 {
		t.Fatalf("the subscriptions were not kept: %d left", len(state.V2RaySubscriptions))
	}
	if len(state.V2RayProfiles) != 2 {
		t.Fatalf("saved configs were not kept: %d left", len(state.V2RayProfiles))
	}
	if len(state.HiddenNodes["provider"]) != 1 {
		t.Fatal("hidden nodes belong to a subscription and should have survived")
	}

	defaults := model.DefaultWhiteVPNSettings()
	if state.WhiteVPN.CountryCode != defaults.CountryCode {
		t.Fatal("the country was not reset")
	}
	if state.WhiteVPN.Connection.Node != "" || len(state.WhiteVPN.Connection.Types) != 0 {
		t.Fatal("the narrowed connection selection was not reset")
	}
	if state.WhiteVPN.DNSPrivacy.Mode != defaults.DNSPrivacy.Mode {
		t.Fatal("the DNS mode was not reset")
	}
	if state.WhiteVPN.KillSwitch.Enabled {
		t.Fatal("the kill switch was not reset")
	}
	if state.WhiteVPN.ChainExitNode != "" {
		t.Fatal("the second hop was not reset")
	}
	if state.WhiteVPN.Language != "" {
		t.Fatal("the language was not reset")
	}
	if state.Theme != model.DefaultAppState().Theme {
		t.Fatal("the theme was not reset")
	}
}

// Consent is a record of something the user did, not a preference. Clearing it
// would not put them back to a fresh install; it would claim they never agreed.
func TestResettingSettingsDoesNotAskForConsentAgain(t *testing.T) {
	app := newSettingsResetTestApp(t)
	app.state.WhiteVPN.AcceptedPrivacyPolicyVersion = 3

	state, err := app.ResetWhiteVPNSettings()
	if err != nil {
		t.Fatal(err)
	}
	if state.WhiteVPN.AcceptedPrivacyPolicyVersion != 3 {
		t.Fatal("a settings reset should not withdraw a consent that was given")
	}
}

// Unlike the full reset, this one runs while connected and must leave the
// session alone: somebody may well be reading the instructions over it.
func TestResettingSettingsDoesNotTouchARunningConnection(t *testing.T) {
	app := newSettingsResetTestApp(t)
	app.state.Runtime.Status = model.RuntimeConnected
	app.state.Runtime.Message = "Connected"
	app.state.Runtime.ActiveConnectionID = "live"
	app.state.Runtime.NodeName = "Tokyo"

	state, err := app.ResetWhiteVPNSettings()
	if err != nil {
		t.Fatalf("a settings reset must not refuse while connected: %v", err)
	}
	if state.Runtime.Status != model.RuntimeConnected {
		t.Fatalf("the connection was disturbed: status is now %q", state.Runtime.Status)
	}
	if state.Runtime.ActiveConnectionID != "live" || state.Runtime.NodeName != "Tokyo" {
		t.Fatal("the running session's identity was cleared")
	}
}

// The subscriptions stay; which one is selected is a setting, and goes back to
// the built-in catalogue the way it does on the phone.
func TestResettingSettingsSelectsTheCatalogueAgain(t *testing.T) {
	app := newSettingsResetTestApp(t)
	app.state.V2RaySubscriptions = []model.V2RaySubscription{
		{ID: "provider", Name: "Provider", URL: "https://example.com/sub"},
	}
	app.state.SelectedSubscriptionID = "provider"

	state, err := app.ResetWhiteVPNSettings()
	if err != nil {
		t.Fatal(err)
	}
	if state.SelectedSubscriptionID != whiteDNSVPNSubscriptionID {
		t.Fatalf("expected the catalogue to be selected, got %q", state.SelectedSubscriptionID)
	}
	if len(state.V2RaySubscriptions) != 1 {
		t.Fatal("selecting the catalogue must not remove the subscription that was selected before")
	}
}

func newSettingsResetTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	store := profiles.NewStore(dir + "/state.json")
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return &App{state: state, store: store, configDir: dir}
}

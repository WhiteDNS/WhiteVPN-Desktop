package profiles

import (
	"testing"

	"whitevpn-desktop/internal/model"
)

// A subscription can vanish between runs — removed on another machine, or a
// state file edited by hand. The selection falls back to the catalogue, and the
// filter chosen for the list that is gone must not fall back with it: that
// would apply "Germany" to a catalogue it was never chosen in and refuse every
// node on it.
func TestACorrectedSelectionTakesItsFilterWithIt(t *testing.T) {
	state := model.DefaultAppState()
	state.SelectedSubscriptionID = "gone"
	state.WhiteVPN.CountryCode = "DE"
	state.WhiteVPN.Connection = model.ConnectionSelection{Types: []string{"vless"}}

	normalized := NormalizeState(state)

	if normalized.SelectedSubscriptionID != model.DefaultAppState().SelectedSubscriptionID {
		t.Fatalf("expected a fallback to the catalogue, got %q", normalized.SelectedSubscriptionID)
	}
	if normalized.WhiteVPN.CountryCode != "" || len(normalized.WhiteVPN.Connection.Types) != 0 {
		t.Fatalf("the vanished list's filter was applied to the catalogue: %+v", normalized.WhiteVPN)
	}
	// And it is not kept for a subscription that no longer exists.
	if _, parked := normalized.WhiteVPN.SubscriptionSelections["gone"]; parked {
		t.Fatalf("kept a choice for a subscription that is gone: %+v", normalized.WhiteVPN.SubscriptionSelections)
	}
}

// Housekeeping, so the file does not grow by one entry for every list anyone
// ever added and removed.
func TestParkedChoicesForUnknownSubscriptionsAreDropped(t *testing.T) {
	state := model.DefaultAppState()
	state.V2RaySubscriptions = []model.V2RaySubscription{{ID: "kept", Name: "Kept", URL: "https://example.com/sub"}}
	state.WhiteVPN.SubscriptionSelections = map[string]model.SubscriptionSelection{
		"kept":                      {CountryCode: "DE"},
		"vanished":                  {CountryCode: "JP"},
		model.BuiltInSubscriptionID: {CountryCode: "NL"},
		model.ManualServerSourceID:  {CountryCode: "FR"},
	}

	normalized := NormalizeState(state)

	parked := normalized.WhiteVPN.SubscriptionSelections
	if _, gone := parked["vanished"]; gone {
		t.Errorf("a choice for a subscription that does not exist was kept: %+v", parked)
	}
	// The catalogue and the manual list are always there to come back to, and
	// neither appears among the user's subscriptions.
	for _, id := range []string{"kept", model.BuiltInSubscriptionID, model.ManualServerSourceID} {
		if _, ok := parked[id]; !ok {
			t.Errorf("dropped the choice for %q, which still exists: %+v", id, parked)
		}
	}
}

// A selection that narrows nothing is the default, and an entry for it would
// grow the file for every subscription anyone ever looked at.
func TestAnEmptyParkedChoiceIsNotStored(t *testing.T) {
	settings := model.DefaultWhiteVPNSettings()
	settings.SubscriptionSelections = map[string]model.SubscriptionSelection{
		"empty": {},
		"real":  {CountryCode: "DE"},
	}

	normalized := model.NormalizeWhiteVPNSettings(settings)

	if _, stored := normalized.SubscriptionSelections["empty"]; stored {
		t.Errorf("stored a choice that narrows nothing: %+v", normalized.SubscriptionSelections)
	}
	if normalized.SubscriptionSelections["real"].CountryCode != "DE" {
		t.Errorf("dropped a real choice: %+v", normalized.SubscriptionSelections)
	}
}

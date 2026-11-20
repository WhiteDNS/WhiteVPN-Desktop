package profiles

import (
	"testing"

	"whitevpn-desktop/internal/model"
)

// Loading a state file with the old chain field carries it over, keyed to the
// subscription it was set up in.
func TestLoadingMigratesTheLegacyChain(t *testing.T) {
	state := model.DefaultAppState()
	state.SelectedSubscriptionID = model.BuiltInSubscriptionID
	state.WhiteVPN.ChainExitNode = "Exit node"
	state = NormalizeState(state)
	want := model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: model.BuiltInSubscriptionID, Node: "Exit node"}
	if state.WhiteVPN.Chain.Exit != want || state.WhiteVPN.Chain.Entry.Mode != model.ChainHopAutomatic || state.WhiteVPN.ChainExitNode != "" {
		t.Fatalf("got %+v / %q", state.WhiteVPN.Chain, state.WhiteVPN.ChainExitNode)
	}
}

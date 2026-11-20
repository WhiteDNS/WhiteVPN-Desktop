package model

import (
	"encoding/json"
	"testing"
)

// The phone's baseCannotBeOffAndBrokenFixedReferencesAreNormalized.
func TestChainNormalization(t *testing.T) {
	chain := NormalizeChainSettings(ChainSettings{
		Entry: ChainHop{Mode: ChainHopOff},
		Exit:  ChainHop{Mode: ChainHopFixed, SubscriptionID: "sub"},
	})
	if chain.Entry != (ChainHop{Mode: ChainHopAutomatic}) || chain.Exit != (ChainHop{Mode: ChainHopOff}) || chain.Active() {
		t.Fatalf("node 1 cannot be off and a half-named node 2 is no node 2: %+v", chain)
	}

	chain = NormalizeChainSettings(ChainSettings{
		Entry: ChainHop{Mode: ChainHopFixed, Node: "missing its list"},
		Exit:  ChainHop{Mode: ChainHopAutomatic, SubscriptionID: "stale", Node: "stale"},
	})
	if chain.Entry != (ChainHop{Mode: ChainHopAutomatic}) || chain.Exit != (ChainHop{Mode: ChainHopAutomatic}) || !chain.Active() {
		t.Fatalf("unexpected: %+v", chain)
	}

	chain = NormalizeChainSettings(ChainSettings{Entry: ChainHop{Mode: "bogus"}, Exit: ChainHop{Mode: "bogus"}})
	if chain != DefaultChainSettings() {
		t.Fatalf("unknown modes are the defaults: %+v", chain)
	}

	fixed := ChainHop{Mode: ChainHopFixed, SubscriptionID: " warp ", Node: " WARP "}
	if got := NormalizeChainSettings(ChainSettings{Entry: fixed}).Entry; got != (ChainHop{Mode: ChainHopFixed, SubscriptionID: "warp", Node: "WARP"}) {
		t.Fatalf("a complete reference is kept, trimmed: %+v", got)
	}
}

// A settings file from before the chain existed reads as no chain.
func TestSettingsWithoutAChainReadAsNoChain(t *testing.T) {
	var settings WhiteVPNSettings
	if err := json.Unmarshal([]byte(`{"language":"fa"}`), &settings); err != nil {
		t.Fatal(err)
	}
	if NormalizeWhiteVPNSettings(settings).Chain != DefaultChainSettings() {
		t.Fatalf("expected no chain: %+v", settings.Chain)
	}
}

// A chain stored as an exit name keeps working: node 2 in the subscription it
// was named in, node 1 the VPN page's choice there.
func TestLegacyChainIsMigrated(t *testing.T) {
	var settings WhiteVPNSettings
	if err := json.Unmarshal([]byte(`{"chainExitNode":" Exit ","connection":{"node":"Pinned"}}`), &settings); err != nil {
		t.Fatal(err)
	}
	migrated := MigrateLegacyChain(settings, "provider")
	want := ChainSettings{
		Entry: ChainHop{Mode: ChainHopFixed, SubscriptionID: "provider", Node: "Pinned"},
		Exit:  ChainHop{Mode: ChainHopFixed, SubscriptionID: "provider", Node: "Exit"},
	}
	if migrated.Chain != want || migrated.ChainExitNode != "" {
		t.Fatalf("got %+v / %q", migrated.Chain, migrated.ChainExitNode)
	}
	if encoded, _ := json.Marshal(migrated); json.Valid(encoded) && containsKey(encoded, "chainExitNode") {
		t.Fatal("the legacy field should not be written back")
	}

	// Automatic stays Automatic, and an empty selection means the built-in list.
	settings.Connection.Node = ""
	migrated = MigrateLegacyChain(settings, "")
	if migrated.Chain.Entry.Mode != ChainHopAutomatic || migrated.Chain.Exit.SubscriptionID != BuiltInSubscriptionID {
		t.Fatalf("got %+v", migrated.Chain)
	}

	// A chain already in the new shape wins over a stray legacy name.
	settings.Chain = ChainSettings{Entry: ChainHop{Mode: ChainHopAutomatic}, Exit: ChainHop{Mode: ChainHopAutomatic}}
	if migrated = MigrateLegacyChain(settings, "provider"); migrated.Chain != settings.Chain || migrated.ChainExitNode != "" {
		t.Fatalf("got %+v", migrated.Chain)
	}

	// No legacy chain, nothing to do.
	if got := MigrateLegacyChain(DefaultWhiteVPNSettings(), "provider").Chain; got != DefaultChainSettings() {
		t.Fatalf("got %+v", got)
	}
}

func containsKey(encoded []byte, key string) bool {
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	_, ok := fields[key]
	return ok
}

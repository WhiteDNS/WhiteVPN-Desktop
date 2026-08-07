package model

import (
	"encoding/json"
	"testing"
)

// The upgrade path. Every settings file written before SetSystemProxy existed
// has no key for it, and a plain bool would read that as false — proxy-only —
// so everyone who updated would find their machine quietly no longer proxied.
func TestSettingsWrittenBeforeThisFieldStillProxyTheMachine(t *testing.T) {
	var settings WhiteVPNSettings
	if err := json.Unmarshal([]byte(`{"tunEnabled":false,"language":"fa"}`), &settings); err != nil {
		t.Fatal(err)
	}
	if !settings.SetSystemProxy {
		t.Fatal("an older settings file must keep proxying the machine")
	}
	// And the rest of the block still decodes.
	if settings.Language != "fa" {
		t.Fatalf("the alias dropped other fields: %#v", settings)
	}
}

// Turning it off has to survive a save and a reload, or the mode cannot be
// chosen at all.
func TestTurningTheSystemProxyOffIsRemembered(t *testing.T) {
	encoded, err := json.Marshal(WhiteVPNSettings{SetSystemProxy: false, ListenPort: 2080})
	if err != nil {
		t.Fatal(err)
	}

	var settings WhiteVPNSettings
	if err := json.Unmarshal(encoded, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.SetSystemProxy {
		t.Fatal("a deliberate off was read back as on")
	}
}

func TestTheSystemProxyStaysOnWhenItWasOn(t *testing.T) {
	var settings WhiteVPNSettings
	if err := json.Unmarshal([]byte(`{"setSystemProxy":true}`), &settings); err != nil {
		t.Fatal(err)
	}
	if !settings.SetSystemProxy {
		t.Fatal("an explicit true was lost")
	}
}

// A port the engine could never bind must be corrected here rather than
// reaching it and failing there, where the cause is much harder to see.
func TestAnUnusablePortBecomesTheDefault(t *testing.T) {
	for _, port := range []int{0, -1, 80, 1023, 65536, 200000} {
		settings := NormalizeWhiteVPNSettings(WhiteVPNSettings{ListenPort: port})
		if settings.ListenPort != DefaultLocalProxyPort {
			t.Errorf("port %d should have become %d, got %d", port, DefaultLocalProxyPort, settings.ListenPort)
		}
	}

	// Zero in particular: that is what a settings block written before this
	// field existed carries, and it has to read as "the usual port" rather than
	// "let the system choose", which would be a different port every run.
	if got := NormalizeWhiteVPNSettings(WhiteVPNSettings{}).ListenPort; got != DefaultLocalProxyPort {
		t.Fatalf("an unset port should be the default, got %d", got)
	}
}

func TestAUsablePortIsKept(t *testing.T) {
	for _, port := range []int{1024, 2080, 7890, 10888, 65535} {
		if got := NormalizeWhiteVPNSettings(WhiteVPNSettings{ListenPort: port}).ListenPort; got != port {
			t.Errorf("port %d should have been kept, got %d", port, got)
		}
	}
}

package model

import (
	"encoding/json"
	"testing"
)

// Automatic ECH is on by default on the phone, and an older settings file has
// no key for it: a plain bool would read that as off for every existing user.
func TestSettingsWrittenBeforeAutoECHLoadWithItOn(t *testing.T) {
	var settings WhiteVPNSettings
	if err := json.Unmarshal([]byte(`{"tlsIntegrityEnabled":true,"setSystemProxy":false}`), &settings); err != nil {
		t.Fatal(err)
	}
	if !settings.AutoECH || !settings.TLSIntegrityEnabled || settings.SetSystemProxy {
		t.Fatalf("legacy settings decoded wrong: %#v", settings)
	}
	if !DefaultWhiteVPNSettings().AutoECH {
		t.Fatal("new installs must start with automatic ECH on")
	}
}

func TestTurningAutoECHOffIsRemembered(t *testing.T) {
	encoded, err := json.Marshal(WhiteVPNSettings{AutoECH: false})
	if err != nil {
		t.Fatal(err)
	}
	var settings WhiteVPNSettings
	if err := json.Unmarshal(encoded, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.AutoECH {
		t.Fatal("a deliberate off was read back as on")
	}

	// The settings page edits the public copy and saves it back.
	encoded, err = json.Marshal(PublicWhiteVPNSettings(settings))
	if err != nil {
		t.Fatal(err)
	}
	var edited WhiteVPNSettings
	if err := json.Unmarshal(encoded, &edited); err != nil {
		t.Fatal(err)
	}
	if edited.AutoECH || !edited.PublicOnly {
		t.Fatalf("the public editor copy lost the setting: %#v", edited)
	}
}

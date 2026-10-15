package model

import (
	"encoding/json"
	"strings"
	"testing"

	"whitevpn-desktop/internal/fragment"
)

func TestFragmentSettingsLoadAndPublicRoundTrip(t *testing.T) {
	var old WhiteVPNSettings
	if err := json.Unmarshal([]byte(`{"language":"fa"}`), &old); err != nil {
		t.Fatal(err)
	}
	old = NormalizeWhiteVPNSettings(old)
	if old.Fragments.Enabled || old.Fragments.RawJSON == "" {
		t.Fatal("old installs must default to fragments off")
	}
	s := DefaultWhiteVPNSettings()
	s.Fragments = fragment.Default()
	s.Fragments.Enabled = true
	s.Fragments.RawJSON = strings.ReplaceAll(s.Fragments.RawJSON, `"maxSplit":"256"`, `"maxSplit":"0"`)
	s = NormalizeWhiteVPNSettings(s)
	bytes, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip WhiteVPNSettings
	if err := json.Unmarshal(bytes, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !roundTrip.Fragments.Enabled || !strings.Contains(roundTrip.Fragments.RawJSON, `"maxSplit": "256"`) {
		t.Fatal("settings lost at persistence/UI boundary")
	}
}

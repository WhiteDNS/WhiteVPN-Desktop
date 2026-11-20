package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestFragmentSettingsSaveAndRejectInvalidEdits(t *testing.T) {
	a := publicAPITestApp(t)
	s := a.GetWhiteVPNSettingsForEdit()
	s.Fragments = a.GetDefaultFragmentSettings()
	s.Fragments.Enabled = true
	s.Fragments.RawJSON = a.GetFragmentPresets()[4]
	if _, err := a.SaveWhiteVPNSettings(s); err != nil {
		t.Fatal(err)
	}
	loaded, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WhiteVPN.Fragments != s.Fragments {
		t.Fatal("fragment preset not persisted")
	}
	before := a.GetWhiteVPNSettingsForEdit().Fragments
	s.Fragments.RawJSON = `{"tcp":[]}`
	if _, err := a.SaveWhiteVPNSettings(s); err == nil {
		t.Fatal("invalid fragment edit accepted")
	}
	if a.GetWhiteVPNSettingsForEdit().Fragments != before {
		t.Fatal("invalid edit replaced working settings")
	}
	if a.GetWhiteVPNSettingsForEdit().DNSPrivacy.DoHURL != "https://dns.example/dns-secret-marker" {
		t.Fatal("fragment save changed DNS credentials")
	}
	for _, raw := range a.GetFragmentPresets() {
		if !strings.Contains(raw, `"maxSplit": "256"`) {
			t.Fatal("legacy split limit returned to UI")
		}
	}
}

// Disposable backend-derived inputs for scripts/fragments-ui-smoke.cjs.
func TestFragmentUIFixture(t *testing.T) {
	path := os.Getenv("WHITEVPN_FRAGMENT_UI_FIXTURE_OUT")
	if path == "" {
		return
	}
	a := publicAPITestApp(t)
	a.state.SelectedSubscriptionID = model.ManualServerSourceID
	a.state.WhiteVPN.Language = "en"
	a.state.WhiteVPN.Fragments = a.GetDefaultFragmentSettings()
	list, err := a.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{"state": a.GetAppState(), "nodes": list, "settings": a.GetWhiteVPNSettingsForEdit(), "presets": a.GetFragmentPresets(), "fragmentDefaults": a.GetDefaultFragmentSettings()}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

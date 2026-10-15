package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func TestFragmentSettingsSaveAndRejectInvalidEdits(t *testing.T) {
	a := fragmentReleaseTestApp(t)
	s := a.GetWhiteVPNSettings()
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
	before := a.GetWhiteVPNSettings().Fragments
	s.Fragments.RawJSON = `{"tcp":[]}`
	if _, err := a.SaveWhiteVPNSettings(s); err == nil {
		t.Fatal("invalid fragment edit accepted")
	}
	if a.GetWhiteVPNSettings().Fragments != before {
		t.Fatal("invalid edit replaced working settings")
	}
	if a.GetWhiteVPNSettings().DNSPrivacy.DoHURL != "https://dns.example/dns-secret-marker" {
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
	a := fragmentReleaseTestApp(t)
	a.state.SelectedSubscriptionID = model.ManualServerSourceID
	a.state.WhiteVPN.Language = "en"
	a.state.WhiteVPN.Fragments = a.GetDefaultFragmentSettings()
	list, err := a.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{"state": a.GetAppState(), "nodes": list, "settings": a.GetWhiteVPNSettings(), "presets": a.GetFragmentPresets(), "fragmentDefaults": a.GetDefaultFragmentSettings()}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func fragmentReleaseTestApp(t *testing.T) *App {
	a := newSnapshotTestApp(t)
	a.store = profiles.NewStore(filepath.Join(a.configDir, "state.json"))
	a.state.V2RayProfiles = []model.V2RayProfile{manualProfile("manual-1", "Demo node", "localhost")}
	a.state.WhiteVPN.DNSPrivacy.DoHURL = "https://dns.example/dns-secret-marker"
	a.state.WhiteVPN.AcceptedPrivacyPolicyVersion = model.CurrentPrivacyPolicyID
	if _, err := a.saveLocked(); err != nil {
		t.Fatal(err)
	}
	return a
}

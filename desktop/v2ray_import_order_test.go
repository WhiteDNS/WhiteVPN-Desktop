package main

import (
	"path/filepath"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func TestImportV2RayProfilesPrependsImportedProfiles(t *testing.T) {
	existing := duplicateTestV2RayProfile("v2ray-existing", "Existing")
	existing.Server = "existing.example.com"
	existing.SubscriptionID = "subscription-existing"
	state := model.DefaultAppState()
	state.V2RayProfiles = []model.V2RayProfile{existing}
	state.SelectedV2RayProfileID = existing.ID
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}
	rawText := "vless://11111111-1111-1111-1111-111111111111@first.example.com:443?security=tls&type=tcp#First\n" +
		"vless://22222222-2222-2222-2222-222222222222@second.example.com:443?security=tls&type=tcp#Second\n" +
		"socks5://user:pass@socks.example.com:1080#NotSupportedByEngine"

	result, err := app.ImportV2RayProfiles(rawText)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imports, got %d", result.Imported)
	}
	if len(result.State.V2RayProfiles) != 3 {
		t.Fatalf("expected imported profiles plus existing profile, got %#v", result.State.V2RayProfiles)
	}
	if result.State.V2RayProfiles[0].Server != "first.example.com" || result.State.V2RayProfiles[1].Server != "second.example.com" {
		t.Fatalf("expected imported profiles at top in import order, got %#v", result.State.V2RayProfiles)
	}
	if result.State.V2RayProfiles[2].ID != existing.ID {
		t.Fatalf("expected existing profile to move after imports, got %#v", result.State.V2RayProfiles)
	}
	if result.State.SelectedV2RayProfileID != result.State.V2RayProfiles[1].ID {
		t.Fatalf("expected last imported profile to remain selected, got %q", result.State.SelectedV2RayProfileID)
	}
	manual, err := app.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(manual.Nodes) != 2 || manual.Nodes[0].Server != "first.example.com" || manual.Nodes[1].Server != "second.example.com" {
		t.Fatalf("expected only manual imports at the top in import order, got %#v", manual.Nodes)
	}
	selected, err := app.SelectSubscription(model.ManualServerSourceID)
	if err != nil {
		t.Fatal(err)
	}
	if selected.SelectedSubscriptionID != model.ManualServerSourceID {
		t.Fatalf("expected Manual to be the selected server source, got %q", selected.SelectedSubscriptionID)
	}

	loaded, err := app.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.V2RayProfiles) != 3 || loaded.V2RayProfiles[0].Server != "first.example.com" || loaded.V2RayProfiles[2].ID != existing.ID {
		t.Fatalf("expected prepended import order to persist, got %#v", loaded.V2RayProfiles)
	}
	if loaded.SelectedSubscriptionID != model.ManualServerSourceID {
		t.Fatalf("expected Manual selection to persist, got %q", loaded.SelectedSubscriptionID)
	}
}

func TestImportV2RayWhiteIPProfilesPrependsGeneratedProfiles(t *testing.T) {
	existing := duplicateTestV2RayProfile("v2ray-existing-white-ip", "Existing")
	existing.Server = "existing.example.com"
	state := model.DefaultAppState()
	state.V2RayProfiles = []model.V2RayProfile{existing}
	state.SelectedV2RayProfileID = existing.ID
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}

	result, err := app.ImportV2RayWhiteIPProfiles(
		"vless://11111111-1111-1111-1111-111111111111@origin.example.com:443?security=tls&type=ws&path=/ws#Origin",
		"69.84.182.49:443\n104.17.121.71:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imports, got %d", result.Imported)
	}
	if len(result.State.V2RayProfiles) != 3 {
		t.Fatalf("expected generated profiles plus existing profile, got %#v", result.State.V2RayProfiles)
	}
	if result.State.V2RayProfiles[0].Server != "69.84.182.49" || result.State.V2RayProfiles[1].Server != "104.17.121.71" {
		t.Fatalf("expected generated profiles at top in generated order, got %#v", result.State.V2RayProfiles)
	}
	if result.State.V2RayProfiles[2].ID != existing.ID {
		t.Fatalf("expected existing profile to move after generated profiles, got %#v", result.State.V2RayProfiles)
	}
	if result.State.SelectedV2RayProfileID != result.State.V2RayProfiles[1].ID {
		t.Fatalf("expected last generated profile to remain selected, got %q", result.State.SelectedV2RayProfileID)
	}
}

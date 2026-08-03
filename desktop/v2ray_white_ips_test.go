package main

import (
	"strings"
	"testing"
)

func TestImportV2RayWhiteIPProfilesAppendsGeneratedProfiles(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	result, err := app.ImportV2RayWhiteIPProfiles(
		"vless://11111111-1111-1111-1111-111111111111@origin.example.com:443?security=tls&type=ws&path=/ws#Origin",
		"69.84.182.49:443\n104.17.121.71:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 || result.SourceProfileCount != 1 || result.WhiteIPCount != 2 {
		t.Fatalf("unexpected import result: %#v", result)
	}
	if len(result.State.V2RayProfiles) != 2 {
		t.Fatalf("expected 2 generated profiles, got %#v", result.State.V2RayProfiles)
	}
	first := result.State.V2RayProfiles[0]
	if first.Server != "69.84.182.49" || first.ServerPort != 443 || first.SubscriptionID != "" {
		t.Fatalf("unexpected first generated profile: %#v", first)
	}
	if first.SNI != "origin.example.com" || first.TransportHost != "origin.example.com" {
		t.Fatalf("expected original hostname fallback, got %#v", first)
	}
	if result.State.SelectedV2RayProfileID != result.State.V2RayProfiles[1].ID {
		t.Fatalf("expected last generated profile to be selected, got %q", result.State.SelectedV2RayProfileID)
	}

	loaded, err := app.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.V2RayProfiles) != 2 {
		t.Fatalf("expected generated profiles to persist, got %#v", loaded.V2RayProfiles)
	}
}

func TestGetDefaultWhiteIPListReturnsBundledCloudflareList(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	raw := app.GetDefaultWhiteIPList()
	if !strings.Contains(raw, "[cloudflare]") || !strings.Contains(raw, "69.84.182.49:443") {
		t.Fatalf("default White IP list missing expected content:\n%s", raw)
	}
}

func TestGenerateV2RayWhiteIPProfilesReturnsConvertedConfigs(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	result, err := app.GenerateV2RayWhiteIPProfiles(
		"vless://11111111-1111-1111-1111-111111111111@origin.example.com:443?security=tls&type=ws&path=/ws#Origin",
		"69.84.182.49:443\n104.17.121.71:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generated != 2 || result.SourceProfileCount != 1 || result.WhiteIPCount != 2 {
		t.Fatalf("unexpected generate result: %#v", result)
	}
	if !strings.Contains(result.ConfigText, "69.84.182.49:443") || !strings.Contains(result.ConfigText, "104.17.121.71:8443") {
		t.Fatalf("generated config text missing converted endpoints:\n%s", result.ConfigText)
	}
	if !strings.Contains(result.ConfigText, "sni=origin.example.com") {
		t.Fatalf("generated config text missing original hostname fallback:\n%s", result.ConfigText)
	}
}

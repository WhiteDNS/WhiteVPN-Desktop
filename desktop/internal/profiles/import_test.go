package profiles

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

const sampleStormDNSProfile = "stormdns://eyJzY2hlbWEiOiJ3aGl0ZWRucy5wcm9maWxlIiwidmVyc2lvbiI6MSwicHJvZmlsZSI6eyJuYW1lIjoiQE1hc2lyX1NlZmlk8J-ViuKtkO-4jygxKSIsInNlcnZlciI6eyJkb21haW4iOiJ2MS5tYXNpci1zZWZpZC5teSIsImVuY3J5cHRpb25fa2V5IjoiVGVsZWdyYW0tQ2hhbm5lbC0tLT5ATWFzaXJfU2VmaWQiLCJlbmNyeXB0aW9uX21ldGhvZCI6MX19fQ"

func TestParseConnectionProfileImportsParsesStormDNSURLAsMasterDNSByDefault(t *testing.T) {
	profiles, err := ParseConnectionProfileImports(sampleStormDNSProfile, "resolver-custom", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	profile := profiles[0]
	if profile.Name != "@Masir_Sefid\U0001f54a\u2b50\ufe0f(1)" {
		t.Fatalf("unexpected profile name: %q", profile.Name)
	}
	if profile.Domain != "v1.masir-sefid.my" {
		t.Fatalf("unexpected domain: %q", profile.Domain)
	}
	if profile.EncryptionKey != "Telegram-Channel--->@Masir_Sefid" {
		t.Fatalf("unexpected key: %q", profile.EncryptionKey)
	}
	if profile.EncryptionMethod != 1 {
		t.Fatalf("unexpected encryption method: %d", profile.EncryptionMethod)
	}
	if profile.ResolverProfileID != "resolver-custom" {
		t.Fatalf("unexpected resolver profile ID: %q", profile.ResolverProfileID)
	}
	if profile.ImportType != model.ImportTypeMasterDNS {
		t.Fatalf("unexpected import type: %q", profile.ImportType)
	}
}

func TestParseConnectionProfileImportsPreservesStormDNSWhenRequested(t *testing.T) {
	profiles, err := ParseConnectionProfileImports(sampleStormDNSProfile, "resolver-custom", model.ImportTypeStormDNS)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].ImportType != model.ImportTypeStormDNS {
		t.Fatalf("unexpected import type: %q", profiles[0].ImportType)
	}
}

func TestParseConnectionProfileImportsParsesMultipleURLs(t *testing.T) {
	first := encodedStormDNSProfile(t, "First", "one.example.com", "key-1", 1)
	second := encodedStormDNSProfile(t, "Second", "two.example.com.", "key-2", 2)

	profiles, err := ParseConnectionProfileImports(strings.Join([]string{first, " ", second}, "\n"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
	if profiles[0].Domain != "one.example.com" || profiles[1].Domain != "two.example.com" {
		t.Fatalf("unexpected imported domains: %#v", profiles)
	}
}

func TestParseConnectionProfileImportsRejectsMissingURLs(t *testing.T) {
	if _, err := ParseConnectionProfileImports("plain text", "", ""); err == nil {
		t.Fatal("expected missing profile error")
	}
}

func TestParseConnectionProfileImportsRejectsInvalidProfile(t *testing.T) {
	link := encodedStormDNSProfile(t, "Broken", "", "key", 1)
	if _, err := ParseConnectionProfileImports(link, "", ""); err == nil {
		t.Fatal("expected invalid profile error")
	}
}

func TestExportConnectionProfileRoundTripsAsMasterDNSURL(t *testing.T) {
	link, err := ExportConnectionProfile(modelConnectionProfile("Export", "export.example.com.", "secret", 3))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "masterdns://") {
		t.Fatalf("expected masterdns link, got %q", link)
	}

	profiles, err := ParseConnectionProfileImports(link, "resolver-export", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 exported profile, got %d", len(profiles))
	}
	profile := profiles[0]
	if profile.Name != "Export" || profile.Domain != "export.example.com" || profile.EncryptionKey != "secret" || profile.EncryptionMethod != 3 {
		t.Fatalf("unexpected exported profile: %#v", profile)
	}
	if profile.ResolverProfileID != "resolver-export" {
		t.Fatalf("unexpected resolver ID: %q", profile.ResolverProfileID)
	}
	if profile.ImportType != model.ImportTypeMasterDNS {
		t.Fatalf("unexpected import type: %q", profile.ImportType)
	}
}

func TestExportConnectionProfilesSkipsIncompleteProfiles(t *testing.T) {
	raw, err := ExportConnectionProfiles([]model.ConnectionProfile{
		modelConnectionProfile("Incomplete", "", "", 1),
		modelConnectionProfile("First", "one.example.com", "key-1", 1),
		modelConnectionProfile("Second", "two.example.com", "key-2", 2),
	})
	if err != nil {
		t.Fatal(err)
	}

	profiles, err := ParseConnectionProfileImports(raw, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 exported profiles, got %d", len(profiles))
	}
	if profiles[0].Domain != "one.example.com" || profiles[1].Domain != "two.example.com" {
		t.Fatalf("unexpected exported domains: %#v", profiles)
	}
}

func TestExportConnectionProfilesRejectsEmptyExport(t *testing.T) {
	if _, err := ExportConnectionProfiles([]model.ConnectionProfile{
		modelConnectionProfile("Incomplete", "", "", 1),
	}); err == nil {
		t.Fatal("expected empty export error")
	}
}

func encodedStormDNSProfile(t *testing.T, name, domain, key string, method int) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema":  stormDNSProfileSchema,
		"version": 1,
		"profile": map[string]any{
			"name": name,
			"server": map[string]any{
				"domain":            domain,
				"encryption_key":    key,
				"encryption_method": method,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return "stormdns://" + base64.RawURLEncoding.EncodeToString(raw)
}

func modelConnectionProfile(name, domain, key string, method int) model.ConnectionProfile {
	return model.ConnectionProfile{
		Name:             name,
		ImportType:       model.ImportTypeMasterDNS,
		Domain:           domain,
		EncryptionKey:    key,
		EncryptionMethod: method,
	}
}

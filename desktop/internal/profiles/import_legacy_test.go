package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"whitevpn-desktop/internal/model"
)

func writeLegacyState(t *testing.T, dir string, state model.AppState) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadLegacyImportReportsNothingWhenSourceIsAbsent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "WhiteDNS Desktop", "state.json")

	offer := ReadLegacyImport(missing)

	if offer.Available {
		t.Fatalf("expected no offer for a missing source, got %#v", offer)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatalf("reading an absent source must not create its directory: %v", err)
	}
}

func TestReadLegacyImportReportsNothingForMalformedSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if offer := ReadLegacyImport(path); offer.Available {
		t.Fatalf("expected no offer for malformed JSON, got %#v", offer)
	}
}

func TestReadLegacyImportLeavesTheSourceUntouched(t *testing.T) {
	legacy := model.DefaultAppState()
	legacy.V2RayProfiles = []model.V2RayProfile{{ID: "p1", Name: "One", Server: "example.com", ServerPort: 443}}
	legacy.WhiteDNSVPNFrontingIPs = []string{"1.2.3.4"}
	path := writeLegacyState(t, filepath.Join(t.TempDir(), "WhiteDNS Desktop"), legacy)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	offer := ReadLegacyImport(path)
	if !offer.Available {
		t.Fatal("expected an offer for a populated source")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("reading the source rewrote it")
	}
	if !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("reading the source changed its modification time")
	}
}

func TestApplyAddsLegacyProfilesWithoutDisplacingExistingOnes(t *testing.T) {
	legacy := model.DefaultAppState()
	legacy.V2RayProfiles = []model.V2RayProfile{
		{ID: "shared", Name: "Legacy name", Server: "legacy.example.com", ServerPort: 443},
		{ID: "legacy-only", Name: "Legacy only", Server: "other.example.com", ServerPort: 443},
	}
	legacy.WhiteDNSVPNFrontingIPs = []string{"1.2.3.4", "5.6.7.8"}
	path := writeLegacyState(t, t.TempDir(), legacy)

	offer := ReadLegacyImport(path)
	if offer.Profiles != 2 || offer.FrontingIPs != 2 {
		t.Fatalf("unexpected offer counts: %#v", offer)
	}

	current := model.DefaultAppState()
	current.V2RayProfiles = []model.V2RayProfile{
		{ID: "shared", Name: "Mine", Server: "mine.example.com", ServerPort: 8443},
	}
	current.WhiteDNSVPNFrontingIPs = []string{"1.2.3.4"}

	next := offer.Apply(current)

	if len(next.V2RayProfiles) != 2 {
		t.Fatalf("expected the colliding profile to be added once, got %#v", next.V2RayProfiles)
	}
	if next.V2RayProfiles[0].Name != "Mine" {
		t.Fatalf("an existing profile must win over the imported one, got %q", next.V2RayProfiles[0].Name)
	}
	if len(next.WhiteDNSVPNFrontingIPs) != 2 {
		t.Fatalf("expected fronting IPs to be deduplicated, got %#v", next.WhiteDNSVPNFrontingIPs)
	}
}

func TestApplyIsANoOpWhenThereIsNothingToImport(t *testing.T) {
	current := model.DefaultAppState()
	current.V2RayProfiles = []model.V2RayProfile{{ID: "p1", Name: "One"}}

	next := LegacyImport{}.Apply(current)

	if len(next.V2RayProfiles) != 1 || next.V2RayProfiles[0].ID != "p1" {
		t.Fatalf("an empty import must change nothing, got %#v", next.V2RayProfiles)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/securestore"
)

const disposableSSHProfile = `{"name":"SSH fixture","kind":"ssh","config":{"ssh":{"host":"localhost","port":22,"username":"test","authType":"password","password":"API-secret-marker"}}}`

func TestEngineProfileAPICredentialsNeverEnterListOrEvents(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("user-scoped DPAPI vault requires Windows")
	}
	a := &App{configDir: t.TempDir()}
	var events []string
	a.emitHook = func(name string, payload any) { raw, _ := json.Marshal(payload); events = append(events, string(raw)) }
	a.initEngineProfiles()
	summary, err := a.SaveEngineProfile(disposableSSHProfile)
	if err != nil {
		t.Fatal(err)
	}
	list, err := a.ListEngineProfiles()
	if err != nil || len(list) != 1 {
		t.Fatal("saved profile not listed")
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "API-secret-marker") {
		t.Fatal("list exposes secret")
	}
	for _, e := range events {
		if strings.Contains(e, "API-secret-marker") {
			t.Fatal("event exposes secret")
		}
	}
	edit, err := a.GetEngineProfileForEdit(summary.ID)
	if err != nil || edit.Config.SSH.Password != "API-secret-marker" {
		t.Fatal("editor cannot recover credentials")
	}
	// Reload from the real encrypted vault, not the original in-memory catalog.
	b := &App{configDir: a.configDir}
	b.initEngineProfiles()
	edit, err = b.GetEngineProfileForEdit(summary.ID)
	if err != nil || edit.Config.SSH.Password != "API-secret-marker" {
		t.Fatal("persisted profile not recoverable")
	}
	data, err := os.ReadFile(filepath.Join(a.configDir, "state-v2", "engine-profiles.vault"))
	if err != nil || strings.Contains(string(data), "API-secret-marker") {
		t.Fatal("plaintext vault")
	}
	if err := a.DeleteEngineProfile(summary.ID, summary.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetEngineProfileForEdit(summary.ID); !errors.Is(err, engineprofiles.ErrNotFound) {
		t.Fatal("deleted profile remains available")
	}
}

func TestEngineProfileVaultCorruptionDoesNotOverwrite(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("user-scoped DPAPI vault requires Windows")
	}
	dir := t.TempDir()
	a := &App{configDir: dir}
	a.initEngineProfiles()
	if _, err := a.SaveEngineProfile(disposableSSHProfile); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state-v2", "engine-profiles.vault")
	if err := os.WriteFile(path, []byte("corrupt-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &App{configDir: dir}
	b.initEngineProfiles()
	if _, err := b.ListEngineProfiles(); !errors.Is(err, securestore.ErrCorrupt) {
		t.Fatal("corrupt vault did not fail closed")
	}
	if _, err := b.SaveEngineProfile(disposableSSHProfile); !errors.Is(err, securestore.ErrCorrupt) {
		t.Fatal("save replaced corrupt vault")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "corrupt-fixture" {
		t.Fatal("corrupt vault overwritten")
	}
}

func TestEngineAvailabilityDoesNotClaimRuntimeFromProfileType(t *testing.T) {
	a := &App{}
	availability := a.GetEngineAvailability()
	if len(availability) != 6 {
		t.Fatal("expected all six engine families")
	}
	for _, entry := range availability {
		if entry.Available || entry.Reason == "" {
			t.Fatal("unimplemented backend reported available")
		}
	}
}

func TestResetDoesNotResurrectEngineCredentials(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("user-scoped DPAPI vault requires Windows")
	}
	a := resetTestApp(t)
	a.initEngineProfiles()
	if _, err := a.SaveEngineProfile(disposableSSHProfile); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResetAppData(); err != nil {
		t.Fatal(err)
	}
	list, err := a.ListEngineProfiles()
	if err != nil || len(list) != 0 {
		t.Fatal("reset retained engine profiles in memory")
	}
	if _, err := a.SaveEngineProfile(`{"name":"second","kind":"psiphon","config":{"psiphon":{"mode":"auto"}}}`); err != nil {
		t.Fatal(err)
	}
	list, err = a.ListEngineProfiles()
	if err != nil || len(list) != 1 || list[0].Kind != engineprofiles.Psiphon {
		t.Fatal("save resurrected a reset profile")
	}
	b := &App{configDir: a.configDir}
	b.initEngineProfiles()
	list, err = b.ListEngineProfiles()
	if err != nil || len(list) != 1 || list[0].Kind != engineprofiles.Psiphon {
		t.Fatal("vault resurrected reset credentials")
	}
}

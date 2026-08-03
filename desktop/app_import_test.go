package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/storm"
)

func TestImportConnectionProfilesAddsProfilesAndPersists(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	app := &App{
		store: store,
		state: model.DefaultAppState(),
	}
	rawText := testStormDNSImportLink(t, "First", "one.example.com", "key-1") + "\n" +
		testStormDNSImportLink(t, "Second", "two.example.com", "key-2")

	result, err := app.ImportConnectionProfiles(rawText, model.ImportTypeMasterDNS)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imports, got %d", result.Imported)
	}
	if len(result.State.ConnectionProfiles) != 3 {
		t.Fatalf("expected default plus imports, got %#v", result.State.ConnectionProfiles)
	}
	if result.State.SelectedConnectionProfileID != result.State.ConnectionProfiles[2].ID {
		t.Fatalf("expected last imported profile to be selected, got %q", result.State.SelectedConnectionProfileID)
	}
	if result.State.ConnectionProfiles[1].ResolverProfileID != model.DefaultResolverProfileID {
		t.Fatalf("expected selected resolver ID on import, got %#v", result.State.ConnectionProfiles[1])
	}
	if result.State.ConnectionProfiles[1].ImportType != model.ImportTypeMasterDNS || result.State.ConnectionProfiles[2].ImportType != model.ImportTypeMasterDNS {
		t.Fatalf("expected legacy stormdns links to import as MasterDNS profiles, got %#v", result.State.ConnectionProfiles)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ConnectionProfiles) != 3 {
		t.Fatalf("expected imports to persist, got %#v", loaded.ConnectionProfiles)
	}
}

func TestSelectConnectionProfileAllowedWhenIdle(t *testing.T) {
	app := testConnectionLockedApp(t, model.RuntimeDisconnected)

	result, err := app.SelectConnectionProfile("connection-other")
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedConnectionProfileID != "connection-other" {
		t.Fatalf("expected idle selection to change, got %q", result.SelectedConnectionProfileID)
	}
	if result.SelectedResolverProfileID != model.DefaultResolverProfileID {
		t.Fatalf("unexpected resolver selection after connection select: %q", result.SelectedResolverProfileID)
	}
}

func TestSelectConnectionProfileRejectedWhileRuntimeActive(t *testing.T) {
	for _, status := range []string{model.RuntimeConnecting, model.RuntimeConnected} {
		t.Run(status, func(t *testing.T) {
			app := testConnectionLockedApp(t, status)

			result, err := app.SelectConnectionProfile("connection-other")
			if err == nil {
				t.Fatal("expected connection selection to be rejected")
			}
			if result.SelectedConnectionProfileID != model.DefaultConnectionProfileID {
				t.Fatalf("selection changed while locked: %q", result.SelectedConnectionProfileID)
			}
			if result.Runtime.ActiveConnectionID != model.DefaultConnectionProfileID {
				t.Fatalf("active connection changed while locked: %q", result.Runtime.ActiveConnectionID)
			}
		})
	}
}

func TestSaveConnectionProfileWhileRuntimeActiveDoesNotSelectSavedProfile(t *testing.T) {
	for _, status := range []string{model.RuntimeConnecting, model.RuntimeConnected} {
		t.Run(status, func(t *testing.T) {
			app := testConnectionLockedApp(t, status)

			result, err := app.SaveConnectionProfile(model.ConnectionProfile{
				Name:              "Saved while active",
				Domain:            "saved.example.com",
				EncryptionKey:     "saved-key",
				EncryptionMethod:  1,
				ResolverProfileID: model.DefaultResolverProfileID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.SelectedConnectionProfileID != model.DefaultConnectionProfileID {
				t.Fatalf("save changed selected connection: %q", result.SelectedConnectionProfileID)
			}
			if result.Runtime.ActiveConnectionID != model.DefaultConnectionProfileID {
				t.Fatalf("save changed active connection: %q", result.Runtime.ActiveConnectionID)
			}
			if !hasTestConnectionNamed(result, "Saved while active") {
				t.Fatalf("saved connection was not added: %#v", result.ConnectionProfiles)
			}
		})
	}
}

func TestImportConnectionProfilesWhileRuntimeActiveDoesNotSelectImportedProfile(t *testing.T) {
	for _, status := range []string{model.RuntimeConnecting, model.RuntimeConnected} {
		t.Run(status, func(t *testing.T) {
			app := testConnectionLockedApp(t, status)
			rawText := testStormDNSImportLink(t, "Imported while active", "imported.example.com", "import-key")

			result, err := app.ImportConnectionProfiles(rawText, model.ImportTypeMasterDNS)
			if err != nil {
				t.Fatal(err)
			}
			if result.Imported != 1 {
				t.Fatalf("expected 1 import, got %d", result.Imported)
			}
			if result.State.SelectedConnectionProfileID != model.DefaultConnectionProfileID {
				t.Fatalf("import changed selected connection: %q", result.State.SelectedConnectionProfileID)
			}
			if result.State.Runtime.ActiveConnectionID != model.DefaultConnectionProfileID {
				t.Fatalf("import changed active connection: %q", result.State.Runtime.ActiveConnectionID)
			}
			if !hasTestConnectionNamed(result.State, "Imported while active") {
				t.Fatalf("imported connection was not added: %#v", result.State.ConnectionProfiles)
			}
		})
	}
}

func TestClearRuntimeLogsReturnsEmptyLogArray(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Logs = []string{"first log"}

	state := app.ClearRuntimeLogs()
	if state.Runtime.Logs == nil {
		t.Fatal("expected cleared logs to be an empty slice, got nil")
	}
	if len(state.Runtime.Logs) != 0 {
		t.Fatalf("expected logs to be empty, got %#v", state.Runtime.Logs)
	}

	raw, err := json.Marshal(state.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"logs":null`) {
		t.Fatalf("cleared logs serialized as null: %s", raw)
	}
	if !strings.Contains(string(raw), `"logs":[]`) {
		t.Fatalf("cleared logs should serialize as an empty array: %s", raw)
	}
}

func TestSaveResolverProfilePreservesLiveRuntimeState(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	app := &App{
		store: store,
		state: model.DefaultAppState(),
	}
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		Message:            "Proxy is connected",
		ActiveConnectionID: model.DefaultConnectionProfileID,
		ListenIP:           "127.0.0.1",
		ListenPort:         2080,
		Progress:           model.ConnectionProgress{Phase: "ready", Percent: 100},
		ResolverState: model.ResolverRuntimeState{
			ActiveResolvers: []string{"1.1.1.1"},
			ValidResolvers:  []string{"1.1.1.1"},
		},
	}
	wantRuntime := app.state.Runtime

	result, err := app.SaveResolverProfile(model.ResolverProfile{
		Name:         "Active",
		ResolverText: "1.1.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Runtime, wantRuntime) {
		t.Fatalf("expected live runtime to be preserved, got %#v", result.Runtime)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Runtime.Status != model.RuntimeDisconnected {
		t.Fatalf("runtime state should not persist as active: %#v", loaded.Runtime)
	}
}

func TestSaveResolverProfileSnapshotDoesNotReplaceActiveSelection(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	state.ResolverProfiles = append(state.ResolverProfiles, model.ResolverProfile{
		ID:           "resolver-current",
		Name:         "Current",
		ResolverText: "8.8.8.8",
	})
	state.SelectedResolverProfileID = "resolver-current"
	state.ConnectionProfiles[0].ResolverProfileID = "resolver-current"
	state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		Message:            "Proxy is connected",
		ActiveConnectionID: model.DefaultConnectionProfileID,
		ListenIP:           "127.0.0.1",
		ListenPort:         2080,
	}
	app := &App{
		store: store,
		state: state,
	}

	var result model.AppState
	for _, snapshot := range []model.ResolverProfile{
		{Name: "Active snapshot", ResolverText: "1.1.1.1"},
		{Name: "Valid snapshot", ResolverText: "9.9.9.9"},
	} {
		var err error
		result, err = app.SaveResolverProfileSnapshot(snapshot)
		if err != nil {
			t.Fatal(err)
		}
	}
	if result.SelectedResolverProfileID != "resolver-current" {
		t.Fatalf("snapshot save changed selected resolver: %#v", result.SelectedResolverProfileID)
	}
	if result.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("snapshot save replaced connection resolver: %#v", result.ConnectionProfiles[0])
	}
	if result.Runtime.Status != model.RuntimeConnected {
		t.Fatalf("snapshot save changed live runtime: %#v", result.Runtime)
	}
	if len(result.ResolverProfiles) != 4 {
		t.Fatalf("expected snapshot resolver to be saved, got %#v", result.ResolverProfiles)
	}
}

func TestDeleteNonActiveResolverWhileConnectingPreservesSelection(t *testing.T) {
	app := testResolverLockedApp(t, model.RuntimeConnecting)

	result, err := app.DeleteResolverProfile("resolver-snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedResolverProfileID != "resolver-current" {
		t.Fatalf("delete changed selected resolver: %q", result.SelectedResolverProfileID)
	}
	if result.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("delete changed connection resolver: %#v", result.ConnectionProfiles[0])
	}
	if hasTestResolverProfile(result, "resolver-snapshot") {
		t.Fatalf("snapshot resolver was not deleted: %#v", result.ResolverProfiles)
	}
}

func TestSelectResolverProfileRejectedWhileConnecting(t *testing.T) {
	app := testResolverLockedApp(t, model.RuntimeConnecting)

	result, err := app.SelectResolverProfile("resolver-other")
	if err == nil {
		t.Fatal("expected resolver selection to be rejected while connecting")
	}
	if result.SelectedResolverProfileID != "resolver-current" {
		t.Fatalf("selection changed selected resolver: %q", result.SelectedResolverProfileID)
	}
	if result.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("selection changed connection resolver: %#v", result.ConnectionProfiles[0])
	}
}

func TestDeleteActiveResolverProfileRejectedWhileConnecting(t *testing.T) {
	app := testResolverLockedApp(t, model.RuntimeConnecting)

	result, err := app.DeleteResolverProfile("resolver-current")
	if err == nil {
		t.Fatal("expected active resolver deletion to be rejected while connecting")
	}
	if result.SelectedResolverProfileID != "resolver-current" {
		t.Fatalf("delete changed selected resolver: %q", result.SelectedResolverProfileID)
	}
	if result.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("delete changed connection resolver: %#v", result.ConnectionProfiles[0])
	}
	if !hasTestResolverProfile(result, "resolver-current") {
		t.Fatalf("active resolver should still exist: %#v", result.ResolverProfiles)
	}
}

func TestSaveAndImportResolverWhileConnectingDoNotSelectNewProfile(t *testing.T) {
	dir := t.TempDir()
	app := testResolverLockedAppWithDir(dir, model.RuntimeConnecting)

	result, err := app.SaveResolverProfile(model.ResolverProfile{
		Name:         "Saved while connecting",
		ResolverText: "4.4.4.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedResolverProfileID != "resolver-current" || result.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("save changed active resolver: selected=%q connection=%q", result.SelectedResolverProfileID, result.ConnectionProfiles[0].ResolverProfileID)
	}
	if !hasTestResolverNamed(result, "Saved while connecting") {
		t.Fatalf("saved resolver was not added: %#v", result.ResolverProfiles)
	}

	result, err = app.SaveResolverProfile(model.ResolverProfile{
		ID:           "resolver-other",
		Name:         "Other updated",
		ResolverText: "9.9.9.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedResolverProfileID != "resolver-current" || result.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("update changed active resolver: selected=%q connection=%q", result.SelectedResolverProfileID, result.ConnectionProfiles[0].ResolverProfileID)
	}
	if !hasTestResolverNamed(result, "Other updated") {
		t.Fatalf("updated resolver was not saved: %#v", result.ResolverProfiles)
	}

	sourcePath := filepath.Join(dir, "import.txt")
	if err := os.WriteFile(sourcePath, []byte("1.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	imported, err := app.importResolverProfileFilePath(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if imported.State.SelectedResolverProfileID != "resolver-current" || imported.State.ConnectionProfiles[0].ResolverProfileID != "resolver-current" {
		t.Fatalf("import changed active resolver: selected=%q connection=%q", imported.State.SelectedResolverProfileID, imported.State.ConnectionProfiles[0].ResolverProfileID)
	}
	if imported.Profile.ID == "" || !hasTestResolverProfile(imported.State, imported.Profile.ID) {
		t.Fatalf("imported resolver was not added: profile=%#v state=%#v", imported.Profile, imported.State.ResolverProfiles)
	}
}

func TestImportResolverProfileFileKeepsLargeListFileBacked(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "resolvers.txt")
	writeLargeResolverFile(t, sourcePath, 100000)
	store := profiles.NewStore(filepath.Join(dir, "state.json"))
	app := &App{
		store: store,
		state: model.DefaultAppState(),
	}
	app.state.ConnectionProfiles[0].Domain = "example.com"
	app.state.ConnectionProfiles[0].EncryptionKey = "secret"

	result, err := app.importResolverProfileFilePath(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 100000 || result.Skipped != 1 {
		t.Fatalf("unexpected import summary: imported=%d skipped=%d", result.Imported, result.Skipped)
	}
	imported := result.Profile
	if imported.ResolverSource != "file" || imported.ResolverText != "" {
		t.Fatalf("expected file-backed profile without inline text, got %#v", imported)
	}
	if len(imported.ResolverPreview) == 0 || len(imported.ResolverPreview) > profiles.ResolverPreviewLimit {
		t.Fatalf("unexpected resolver preview size: %d", len(imported.ResolverPreview))
	}
	if _, err := os.Stat(imported.ResolverFile); err != nil {
		t.Fatalf("expected managed resolver file: %v", err)
	}

	cfg, err := storm.BuildLaunchConfig(result.State)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResolversPath != imported.ResolverFile || cfg.Resolvers != "" {
		t.Fatalf("expected launch config to use managed resolver path, got path=%q inline=%q", cfg.ResolversPath, cfg.Resolvers)
	}

	rawState, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawState), "10.1.134.159") {
		t.Fatal("persisted state should not contain the full imported resolver list")
	}

	if _, err := app.DeleteResolverProfile(imported.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(imported.ResolverFile); !os.IsNotExist(err) {
		t.Fatalf("expected managed resolver file to be deleted, got %v", err)
	}
}

func TestStoreLoadMigratesLegacyLargeInlineResolverProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := model.DefaultAppState()
	var raw strings.Builder
	for i := 0; i < profiles.MaxInlineResolverEntries+1; i++ {
		fmt.Fprintf(&raw, "10.0.%d.%d\n", i/256, i%256)
	}
	state.ResolverProfiles = append(state.ResolverProfiles, model.ResolverProfile{
		ID:           "legacy-large",
		Name:         "Legacy Large",
		ResolverText: raw.String(),
	})
	state.SelectedResolverProfileID = "legacy-large"
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := profiles.NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	var migrated model.ResolverProfile
	for _, profile := range loaded.ResolverProfiles {
		if profile.ID == "legacy-large" {
			migrated = profile
			break
		}
	}
	if migrated.ResolverSource != "file" || migrated.ResolverText != "" || migrated.ResolverCount != profiles.MaxInlineResolverEntries+1 {
		t.Fatalf("expected migrated file-backed profile, got %#v", migrated)
	}
	if _, err := os.Stat(migrated.ResolverFile); err != nil {
		t.Fatalf("expected migrated resolver file: %v", err)
	}
	rawState, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawState), "10.0.19.136") {
		t.Fatal("migrated state should not retain inline resolver text")
	}
}

func TestBrandDisplayTextRewritesStormDNSOnce(t *testing.T) {
	got := brandDisplayText("StormDNS Client via MasterDNS/StormDNS")
	want := "MasterDNS/StormDNS Client via MasterDNS/StormDNS"
	if got != want {
		t.Fatalf("unexpected brand text: %q", got)
	}
}

func testConnectionLockedApp(t *testing.T, status string) *App {
	t.Helper()
	state := model.DefaultAppState()
	state.ConnectionProfiles = append(state.ConnectionProfiles, model.ConnectionProfile{
		ID:                "connection-other",
		Name:              "Other",
		Domain:            "other.example.com",
		EncryptionKey:     "other-key",
		EncryptionMethod:  1,
		ResolverProfileID: model.DefaultResolverProfileID,
	})
	state.SelectedConnectionProfileID = model.DefaultConnectionProfileID
	state.Runtime = model.RuntimeStatus{
		Status:             status,
		Message:            "Proxy is active",
		ActiveConnectionID: model.DefaultConnectionProfileID,
	}
	return &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}
}

func testResolverLockedApp(t *testing.T, status string) *App {
	t.Helper()
	return testResolverLockedAppWithDir(t.TempDir(), status)
}

func testResolverLockedAppWithDir(dir string, status string) *App {
	state := model.DefaultAppState()
	state.ResolverProfiles = append(state.ResolverProfiles,
		model.ResolverProfile{ID: "resolver-current", Name: "Current", ResolverText: "8.8.8.8"},
		model.ResolverProfile{ID: "resolver-other", Name: "Other", ResolverText: "9.9.9.9"},
		model.ResolverProfile{ID: "resolver-snapshot", Name: "Snapshot", ResolverText: "1.1.1.1"},
	)
	state.SelectedResolverProfileID = "resolver-current"
	state.ConnectionProfiles[0].ResolverProfileID = "resolver-current"
	state.Runtime = model.RuntimeStatus{
		Status:             status,
		Message:            "Proxy is starting",
		ActiveConnectionID: model.DefaultConnectionProfileID,
	}
	return &App{
		store: profiles.NewStore(filepath.Join(dir, "state.json")),
		state: state,
	}
}

func hasTestResolverProfile(state model.AppState, id string) bool {
	for _, profile := range state.ResolverProfiles {
		if profile.ID == id {
			return true
		}
	}
	return false
}

func hasTestResolverNamed(state model.AppState, name string) bool {
	for _, profile := range state.ResolverProfiles {
		if profile.Name == name {
			return true
		}
	}
	return false
}

func hasTestConnectionNamed(state model.AppState, name string) bool {
	for _, profile := range state.ConnectionProfiles {
		if profile.Name == name {
			return true
		}
	}
	return false
}

func writeLargeResolverFile(t *testing.T, path string, count int) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		if _, err := fmt.Fprintf(file, "10.%d.%d.%d\n", (i>>16)&255, (i>>8)&255, i&255); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if _, err := fmt.Fprintln(file, "not-a-resolver"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func testStormDNSImportLink(t *testing.T, name, domain, key string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema":  "whitedns.profile",
		"version": 1,
		"profile": map[string]any{
			"name": name,
			"server": map[string]any{
				"domain":            domain,
				"encryption_key":    key,
				"encryption_method": 1,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return "stormdns://" + base64.RawURLEncoding.EncodeToString(raw)
}

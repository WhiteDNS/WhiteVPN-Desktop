package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func TestReorderConnectionProfilesPersistsOrderAndKeepsDefaultProtected(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	state.ConnectionProfiles = append(state.ConnectionProfiles,
		model.ConnectionProfile{ID: "connection-one", Name: "One", EncryptionMethod: 1},
		model.ConnectionProfile{ID: "connection-two", Name: "Two", EncryptionMethod: 1},
	)
	state.SelectedConnectionProfileID = "connection-one"
	app := &App{store: store, state: state}

	result, err := app.ReorderConnectionProfiles([]string{"connection-two", model.DefaultConnectionProfileID, "connection-one"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"connection-two", model.DefaultConnectionProfileID, "connection-one"}
	if got := connectionProfileIDs(result.ConnectionProfiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reordered connections: got %#v want %#v", got, want)
	}
	if result.SelectedConnectionProfileID != "connection-one" {
		t.Fatalf("selection changed after reorder: %q", result.SelectedConnectionProfileID)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := connectionProfileIDs(loaded.ConnectionProfiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered connections did not persist: got %#v want %#v", got, want)
	}
	if _, err := app.DeleteConnectionProfile(model.DefaultConnectionProfileID); err == nil {
		t.Fatal("expected moved default connection profile to remain protected")
	}
}

func TestReorderResolverProfilesPersistsOrderAndSelection(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	state.ResolverProfiles = append(state.ResolverProfiles,
		model.ResolverProfile{ID: "resolver-one", Name: "One", ResolverText: "1.1.1.1"},
		model.ResolverProfile{ID: "resolver-two", Name: "Two", ResolverText: "8.8.8.8"},
	)
	state.SelectedResolverProfileID = "resolver-one"
	state.ConnectionProfiles[0].ResolverProfileID = "resolver-one"
	app := &App{store: store, state: state}

	result, err := app.ReorderResolverProfiles([]string{"resolver-two", model.DefaultResolverProfileID, "resolver-one"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"resolver-two", model.DefaultResolverProfileID, "resolver-one"}
	if got := resolverProfileIDs(result.ResolverProfiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reordered resolvers: got %#v want %#v", got, want)
	}
	if result.SelectedResolverProfileID != "resolver-one" || result.ConnectionProfiles[0].ResolverProfileID != "resolver-one" {
		t.Fatalf("resolver selection changed after reorder: %#v", result)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := resolverProfileIDs(loaded.ResolverProfiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered resolvers did not persist: got %#v want %#v", got, want)
	}
	if _, err := app.DeleteResolverProfile(model.DefaultResolverProfileID); err == nil {
		t.Fatal("expected moved default resolver profile to remain protected")
	}
}

func TestReorderSettingsProfilesPersistsOrderAndSelection(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	one := model.DefaultSettingsProfile()
	one.ID = "settings-one"
	one.Name = "One"
	two := model.DefaultSettingsProfile()
	two.ID = "settings-two"
	two.Name = "Two"
	state.SettingsProfiles = append(state.SettingsProfiles, one, two)
	state.SelectedSettingsProfileID = "settings-one"
	app := &App{store: store, state: state}

	result, err := app.ReorderSettingsProfiles([]string{"settings-two", model.DefaultSettingsProfileID, "settings-one"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"settings-two", model.DefaultSettingsProfileID, "settings-one"}
	if got := settingsProfileIDs(result.SettingsProfiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reordered settings: got %#v want %#v", got, want)
	}
	if result.SelectedSettingsProfileID != "settings-one" {
		t.Fatalf("selection changed after reorder: %q", result.SelectedSettingsProfileID)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := settingsProfileIDs(loaded.SettingsProfiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered settings did not persist: got %#v want %#v", got, want)
	}
	if _, err := app.DeleteSettingsProfile(model.DefaultSettingsProfileID); err == nil {
		t.Fatal("expected moved default settings profile to remain protected")
	}
}

func TestSaveSettingsProfileRejectsDefaultEdits(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	app := &App{store: store, state: state}

	edited := model.DefaultSettingsProfile()
	edited.Name = "Edited default"
	edited.ListenPort = 32000

	result, err := app.SaveSettingsProfile(edited)
	if err == nil || !strings.Contains(err.Error(), "default settings profile cannot be edited") {
		t.Fatalf("expected default settings edit rejection, got %v", err)
	}
	if result.SettingsProfiles[0] != model.DefaultSettingsProfile() {
		t.Fatalf("default settings profile was mutated: %#v", result.SettingsProfiles[0])
	}
	if app.state.SettingsProfiles[0] != model.DefaultSettingsProfile() {
		t.Fatalf("app state default settings profile was mutated: %#v", app.state.SettingsProfiles[0])
	}
}

func TestReorderProfilesRejectsInvalidIDsWithoutMutation(t *testing.T) {
	original := []model.ConnectionProfile{
		model.DefaultConnectionProfile(),
		{ID: "connection-one", Name: "One", EncryptionMethod: 1},
		{ID: "connection-two", Name: "Two", EncryptionMethod: 1},
	}
	tests := []struct {
		name    string
		ids     []string
		wantErr string
	}{
		{name: "missing ID", ids: []string{model.DefaultConnectionProfileID, "connection-one"}, wantErr: "exactly 3 IDs"},
		{name: "unknown ID", ids: []string{model.DefaultConnectionProfileID, "connection-one", "missing"}, wantErr: "unknown ID"},
		{name: "duplicate ID", ids: []string{model.DefaultConnectionProfileID, "connection-one", "connection-one"}, wantErr: "duplicate ID"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := &App{
				store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
				state: model.AppState{
					SelectedConnectionProfileID: model.DefaultConnectionProfileID,
					SelectedResolverProfileID:   model.DefaultResolverProfileID,
					SelectedSettingsProfileID:   model.DefaultSettingsProfileID,
					ConnectionProfiles:          append([]model.ConnectionProfile(nil), original...),
					ResolverProfiles:            []model.ResolverProfile{model.DefaultResolverProfile()},
					SettingsProfiles:            []model.SettingsProfile{model.DefaultSettingsProfile()},
					Runtime:                     model.DefaultAppState().Runtime,
				},
			}

			if _, err := app.ReorderConnectionProfiles(test.ids); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected %q error, got %v", test.wantErr, err)
			}
			if got := connectionProfileIDs(app.state.ConnectionProfiles); !reflect.DeepEqual(got, []string{model.DefaultConnectionProfileID, "connection-one", "connection-two"}) {
				t.Fatalf("invalid reorder mutated state: %#v", got)
			}
		})
	}
}

func connectionProfileIDs(profiles []model.ConnectionProfile) []string {
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ID)
	}
	return ids
}

func resolverProfileIDs(profiles []model.ResolverProfile) []string {
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ID)
	}
	return ids
}

func settingsProfileIDs(profiles []model.SettingsProfile) []string {
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ID)
	}
	return ids
}

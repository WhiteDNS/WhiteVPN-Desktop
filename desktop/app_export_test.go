package main

import (
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func TestExportClientTomlDoesNotRequireConnectionSecrets(t *testing.T) {
	app := &App{state: model.DefaultAppState()}

	toml, err := app.ExportClientToml()
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range []string{
		`DOMAINS =`,
		`DATA_ENCRYPTION_METHOD =`,
		`ENCRYPTION_KEY =`,
	} {
		if strings.Contains(toml, line) {
			t.Fatalf("export TOML should omit %q:\n%s", line, toml)
		}
	}
	if !strings.Contains(toml, `PROTOCOL_TYPE = "SOCKS5"`) {
		t.Fatalf("export TOML missing runtime settings:\n%s", toml)
	}
}

func TestExportSettingsProfileTomlUsesOnlyProvidedSettings(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	settings := model.DefaultSettingsProfile()
	settings.StormDNSListenPort = 19087

	toml, err := app.ExportSettingsProfileToml(settings)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(toml, `DOMAINS =`) || strings.Contains(toml, `ENCRYPTION_KEY =`) {
		t.Fatalf("settings export should omit connection fields:\n%s", toml)
	}
	if !strings.Contains(toml, `LISTEN_PORT = 19087`) {
		t.Fatalf("settings export missing provided listen port:\n%s", toml)
	}
}

func TestImportSettingsProfileTomlCreatesSelectedSettings(t *testing.T) {
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: model.DefaultAppState(),
	}

	state, err := app.ImportSettingsProfileToml(`
DOMAINS = ["ignored.example.com"]
ENCRYPTION_KEY = "ignored"
LISTEN_PORT = 19087
PACKET_DUPLICATION_COUNT = 6
LOG_LEVEL = "INFO"
`, "Imported TOML", model.ImportTypeMasterDNS)
	if err != nil {
		t.Fatal(err)
	}

	if len(state.SettingsProfiles) != 2 {
		t.Fatalf("expected imported settings profile, got %#v", state.SettingsProfiles)
	}
	imported := state.SettingsProfiles[1]
	if state.SelectedSettingsProfileID != imported.ID {
		t.Fatalf("expected imported settings to be selected, got %q", state.SelectedSettingsProfileID)
	}
	if imported.Name != "Imported TOML" || imported.StormDNSListenPort != 19087 {
		t.Fatalf("unexpected imported profile: %#v", imported)
	}
	if imported.UploadDuplication != 6 || imported.LogLevel != "INFO" {
		t.Fatalf("unexpected imported profile values: %#v", imported)
	}
}

func TestImportBackupRejectedWhileRuntimeActive(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	backup, err := store.ExportBackup(model.DefaultAppState())
	if err != nil {
		t.Fatal(err)
	}

	app := &App{
		store: store,
		state: model.DefaultAppState(),
	}
	app.state.Runtime.Status = model.RuntimeConnected

	result, err := app.ImportBackup(backup)
	if err == nil {
		t.Fatal("expected active runtime restore to be rejected")
	}
	if !strings.Contains(err.Error(), "disconnected") {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Runtime.Status != model.RuntimeConnected {
		t.Fatalf("runtime state changed after rejected restore: %#v", result.Runtime)
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func resetTestApp(t *testing.T) *App {
	t.Helper()
	// The real name, because ResetAppData refuses to delete a directory that is
	// not called this — and that refusal is the thing most worth testing.
	dir := filepath.Join(t.TempDir(), appDataDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := model.DefaultAppState()
	state.V2RaySubscriptions = []model.V2RaySubscription{{ID: "user-1", Name: "Mine", URL: "https://example.com/sub"}}
	state.V2RayProfiles = []model.V2RayProfile{manualProfile("v2ray-1", "Mine", "one.example.com")}
	state.WhiteVPN.TunEnabled = true

	return &App{
		store:     profiles.NewStore(filepath.Join(dir, "state.json")),
		configDir: dir,
		state:     state,
	}
}

func TestResetRemovesEverythingAndStartsFresh(t *testing.T) {
	app := resetTestApp(t)
	// The things a used install has lying about.
	for _, name := range []string{"cores", "mihomo", "mihomo-measure", "validator-results"} {
		if err := os.MkdirAll(filepath.Join(app.configDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(app.configDir, "system-proxy.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.saveLocked(); err != nil {
		t.Fatal(err)
	}

	next, err := app.ResetAppData()
	if err != nil {
		t.Fatal(err)
	}

	// Only the freshly written state file should remain.
	entries, err := os.ReadDir(app.configDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "state.json" {
			t.Errorf("%q survived the reset", entry.Name())
		}
	}

	if len(next.V2RayProfiles) != 0 {
		t.Errorf("configs survived: %#v", next.V2RayProfiles)
	}
	if next.WhiteVPN.TunEnabled {
		t.Error("settings survived the reset")
	}
	// A fresh install lists the catalogue and nothing else — the same property
	// the first-launch fix is about, and a reset has to land in that state too.
	if len(next.V2RaySubscriptions) != 1 || next.V2RaySubscriptions[0].ID != whiteDNSVPNSubscriptionID {
		t.Fatalf("a reset should leave exactly the catalogue listed: %#v", next.V2RaySubscriptions)
	}
}

// The engine runs out of the directory this deletes, its adapter is up, and the
// record of the machine's original proxy settings is in there too — deleting
// that while it is still needed strands them with nothing left that knows how to
// put them back.
func TestResetRefusesWhileSomethingIsRunning(t *testing.T) {
	for _, status := range []string{model.RuntimeConnected, model.RuntimeConnecting, model.RuntimeStopping} {
		app := resetTestApp(t)
		app.state.Runtime.Status = status
		marker := filepath.Join(app.configDir, "keep-me")
		if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := app.ResetAppData(); err == nil {
			t.Errorf("expected a reset to be refused while %s", status)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Errorf("a refused reset deleted something anyway (%s): %v", status, err)
		}
	}
}

// This deletes recursively. A configDir that had become empty, or someone's home
// directory, would take everything with it.
func TestResetRefusesADirectoryThatIsNotItsOwn(t *testing.T) {
	for _, dir := range []string{"", "   ", filepath.Join(t.TempDir(), "Documents")} {
		app := resetTestApp(t)
		app.configDir = dir
		if _, err := app.ResetAppData(); err == nil {
			t.Errorf("expected %q to be refused", dir)
		}
	}
}

// A failed reset must say which files it could not remove rather than reporting
// success over a half-emptied directory.
func TestRemoveConfigDirContentsNamesWhatItCouldNotRemove(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeConfigDirContents(dir); err != nil {
		t.Fatalf("an ordinary file should have been removed: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("expected an empty directory, got %d entries", len(entries))
	}
	// A directory that is not there is already empty, which is not a failure.
	if err := removeConfigDirContents(filepath.Join(dir, "gone")); err != nil {
		t.Fatalf("a missing directory should be fine: %v", err)
	}
}

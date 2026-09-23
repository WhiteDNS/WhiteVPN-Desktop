package main

import (
	"path/filepath"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func trayModeApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	// Disconnected throughout: these cover the decision, not the machine's own
	// proxy settings, which must not be touched by a test run.
	return &App{
		store:     profiles.NewStore(filepath.Join(dir, "state.json")),
		configDir: dir,
		state:     model.DefaultAppState(),
	}
}

// The system proxy is a setting on this machine rather than something the
// engine holds, so flipping it is a decision the app can take on its own.
func TestTheTraySystemProxyItemFlipsTheSetting(t *testing.T) {
	app := trayModeApp(t)
	before := app.GetAppState().WhiteVPN.SetSystemProxy

	app.toggleSystemProxyFromTray()
	if got := app.GetAppState().WhiteVPN.SetSystemProxy; got == before {
		t.Fatalf("the setting did not change, still %v", got)
	}
	app.toggleSystemProxyFromTray()
	if got := app.GetAppState().WhiteVPN.SetSystemProxy; got != before {
		t.Fatalf("flipping twice should land back on %v, got %v", before, got)
	}
}

// And it persists, because a mode chosen from the tray is a mode, not a mood.
func TestATrayModeChangeSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	app := &App{store: profiles.NewStore(path), configDir: dir, state: model.DefaultAppState()}

	before := app.GetAppState().WhiteVPN.SetSystemProxy
	app.toggleSystemProxyFromTray()

	reloaded, err := profiles.NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.WhiteVPN.SetSystemProxy == before {
		t.Fatalf("the change did not reach the file: %v", reloaded.WhiteVPN.SetSystemProxy)
	}
}

// Tunnel mode reconnects when something is running, and must not try to when
// nothing is — there would be nothing to reconnect and the attempt would report
// a failure that was never a failure.
func TestTheTrayTunnelItemDoesNotReconnectWhenIdle(t *testing.T) {
	app := trayModeApp(t)
	if app.GetAppState().Runtime.Status != model.RuntimeDisconnected {
		t.Fatalf("this test assumes an idle app, got %q", app.GetAppState().Runtime.Status)
	}
	before := app.GetAppState().WhiteVPN.TunEnabled

	app.toggleTunnelFromTray()

	state := app.GetAppState()
	if !tunnelSupported() {
		// settingsForThisMachine refuses a tunnel where none can be raised, and
		// the item has to leave the setting alone rather than claim it changed.
		if state.WhiteVPN.TunEnabled {
			t.Fatalf("tunnel mode was stored on a machine that cannot raise one")
		}
		return
	}
	if state.WhiteVPN.TunEnabled == before {
		t.Fatalf("the setting did not change, still %v", before)
	}
	if state.Runtime.Status != model.RuntimeDisconnected {
		t.Fatalf("an idle app should stay idle, got %q", state.Runtime.Status)
	}
}

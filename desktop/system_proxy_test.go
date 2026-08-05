package main

import (
	"os"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/sysproxy"
)

// The backup exists so that a crash is survivable: the machine's proxy has to
// go back to what it was, and the only record of what it was is this file.
func TestSystemProxyBackupSurvivesToBeRestored(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}

	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("a fresh directory holds no backup, so nothing should be restored")
	}

	want := sysproxy.State{Enabled: true, Server: "127.0.0.1:10808", Override: "<local>"}
	if err := app.writeSystemProxyBackup(want); err != nil {
		t.Fatal(err)
	}
	got, ok := app.readSystemProxyBackup()
	if !ok || !got.SameAs(want) {
		t.Fatalf("the backup did not survive: got %#v, want %#v", got, want)
	}
}

// A file that cannot be read is worse than none: kept, it would have the app
// trying to restore something it cannot understand on every start, forever.
func TestUnreadableSystemProxyBackupIsDiscarded(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	if err := os.WriteFile(app.systemProxyBackupPath(), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("expected an unreadable backup to be refused")
	}
	if _, err := os.Stat(app.systemProxyBackupPath()); !os.IsNotExist(err) {
		t.Fatal("expected an unreadable backup to be removed rather than retried forever")
	}
}

// Restoring when nothing was changed must be a no-op, because it runs on every
// stop — including the ones that follow a connection that never came up.
func TestRestoringWithNoBackupChangesNothing(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	app.state.Runtime.SystemProxy = true
	app.restoreSystemProxy()
	if !app.state.Runtime.SystemProxy {
		t.Fatal("with no backup there is nothing to restore, and nothing to report")
	}
}

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

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

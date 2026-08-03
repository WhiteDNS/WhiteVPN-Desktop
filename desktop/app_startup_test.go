package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestNewAppEnsuresAppDataWritableBeforeStateLoad(t *testing.T) {
	previous := ensureAppDataWritable
	defer func() { ensureAppDataWritable = previous }()

	sentinel := errors.New("stop before state load")
	called := false
	ensureAppDataWritable = func(_ context.Context, dir string) error {
		called = true
		if filepath.Base(dir) != "WhiteDNS Desktop" {
			t.Fatalf("unexpected app data directory: %q", dir)
		}
		return sentinel
	}

	app, err := NewApp()
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected startup to return guard error, got %v", err)
	}
	if app != nil {
		t.Fatalf("expected app construction to stop before state load, got %#v", app)
	}
	if !called {
		t.Fatal("expected NewApp to check app data permissions")
	}
}

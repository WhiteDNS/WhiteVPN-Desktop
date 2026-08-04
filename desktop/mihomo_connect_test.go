package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMihomoEngineSelectedOnlyOnAnExactOptIn(t *testing.T) {
	for value, want := range map[string]bool{
		"mihomo":     true,
		"MIHOMO":     true,
		" mihomo ":   true,
		"xray":       false,
		"":           false,
		"mihomo-ish": false,
	} {
		t.Setenv(engineEnvVar, value)
		if got := mihomoEngineSelected(); got != want {
			t.Errorf("%s=%q selected=%v, want %v", engineEnvVar, value, got, want)
		}
	}
}

// A missing engine has to say so plainly. It is the first thing anyone opting in
// will hit, and "connection failed" would send them looking in the wrong place.
func TestFindMihomoCoreExplainsItselfWhenAbsent(t *testing.T) {
	t.Setenv("WHITEVPN_MIHOMO_BIN", filepath.Join(t.TempDir(), "absent.exe"))

	_, err := findMihomoCore()
	if err == nil {
		t.Fatal("expected an error for a path that does not exist")
	}
	if !strings.Contains(err.Error(), "absent.exe") {
		t.Fatalf("the error should name the path it looked at: %v", err)
	}
}

func TestFindMihomoCoreAcceptsAnOverride(t *testing.T) {
	name := "mihomo-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("not really an engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHITEVPN_MIHOMO_BIN", path)

	found, err := findMihomoCore()
	if err != nil {
		t.Fatal(err)
	}
	if found != path {
		t.Fatalf("found %q, want %q", found, path)
	}
}

// Stopping when nothing is running must be harmless: StopConnection calls it
// before falling through to the Xray path, and every disconnect goes through it.
func TestStopMihomoIsSafeWithNoSession(t *testing.T) {
	app := &App{}
	if app.stopMihomo() {
		t.Fatal("reported stopping a session that was never started")
	}
}

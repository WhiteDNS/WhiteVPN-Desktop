package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A missing engine has to say so plainly. It is the first thing anyone opting in
// will hit, and "connection failed" would send them looking in the wrong place.
func TestFindMihomoCoreExplainsItselfWhenAbsent(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows never reads the override. The core is launched elevated there,
		// so it comes only from the copy inside the application rather than from
		// an environment variable another local process could point elsewhere —
		// which means there is no missing path for it to complain about.
		t.Skip("Windows intentionally uses only the embedded elevated core")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows intentionally uses only the embedded elevated core")
	}
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

func TestWriteEmbeddedFileReplacesSameSizedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	if err := os.WriteFile(path, []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeEmbeddedFile(path, []byte("safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "safe" {
		t.Fatalf("got %q, want embedded content", got)
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

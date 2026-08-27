package main

import (
	"reflect"
	"runtime"
	"testing"

	"whitevpn-desktop/internal/model"
)

// The switch could never have worked where there is no way to raise the core,
// and left stored as on it is unreachable — the interface no longer offers the
// mode it belongs to, so every connection would fail with a sentence about an
// unimplemented function and no way out short of resetting the app.
func TestTheTunnelIsDroppedWhereItCannotRun(t *testing.T) {
	got := settingsForThisMachine(model.WhiteVPNSettings{TunEnabled: true})
	if got.TunEnabled != tunnelSupported() {
		t.Fatalf("TunEnabled=%v on %s, where tunnelSupported()=%v", got.TunEnabled, runtime.GOOS, tunnelSupported())
	}
}

// Only the tunnel is touched. Everything else a settings file says is the user's
// and must survive.
func TestNothingElseIsTouched(t *testing.T) {
	before := model.WhiteVPNSettings{
		TunEnabled:     false,
		SetSystemProxy: false,
		AllowLAN:       true,
		ListenPort:     7890,
		Language:       "fa",
	}
	after := settingsForThisMachine(before)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("settings were changed:\nbefore %#v\nafter  %#v", before, after)
	}
}

// Off stays off wherever it runs — this drops the tunnel, it never enables it.
func TestItNeverTurnsTheTunnelOn(t *testing.T) {
	if settingsForThisMachine(model.WhiteVPNSettings{TunEnabled: false}).TunEnabled {
		t.Fatal("the tunnel was turned on by something meant only to drop it")
	}
}

// Windows and Linux have an elevation path; macOS does not yet. This is the
// list the doc comment describes, asserted rather than left to be read.
func TestTheTunnelIsOfferedWhereTheCoreCanBeRaised(t *testing.T) {
	got := tunnelSupported()
	switch runtime.GOOS {
	case "windows":
		if !got {
			t.Fatal("Windows has ShellExecuteExW and must offer the tunnel")
		}
	case "linux":
		// Not asserted either way: whether it is offered depends on this
		// machine having pkexec, which is the whole point of asking rather
		// than hard-coding. What must hold is that the answer agrees with the
		// reason for it.
		if got != linuxCanElevate() {
			t.Fatalf("tunnelSupported()=%v but linuxCanElevate()=%v", got, linuxCanElevate())
		}
	default:
		if got {
			t.Fatalf("%s has no elevation path wired up, so the tunnel must not be offered", runtime.GOOS)
		}
	}
}

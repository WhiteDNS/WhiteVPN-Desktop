//go:build linux

package sysproxy

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The probe decides which backends a machine really has. A binary on PATH is
// not the question — gsettings with no session behind it, or KDE's writer
// without its reader, both used to pass and then fail later, in front of the
// user. These tests stand in for the session this development host does not
// have.
func setProbe(t *testing.T, onPath []string, answers map[string]error) {
	t.Helper()
	prevProbe, prevFind := probeRun, findBinary
	probeRun = func(name string, _ ...string) error { return answers[name] }
	findBinary = func(name string) bool { return slices.Contains(onPath, name) }
	t.Cleanup(func() { probeRun, findBinary = prevProbe, prevFind })
}

func TestBackendsNeedBothHalvesOfKDE(t *testing.T) {
	setProbe(t,
		[]string{"gsettings", "kwriteconfig6", "kreadconfig5"},
		map[string]error{
			"gsettings":    nil,
			"kreadconfig5": nil,
		})
	got := usableBackends()
	names := make([]string, 0, len(got))
	for _, b := range got {
		names = append(names, b.name)
	}
	if !slices.Equal(names, []string{"gnome", "kde5"}) {
		// kwriteconfig6 without kreadconfig6 is a writer for a file nothing can
		// read back; it must not be offered.
		t.Fatalf("got %v, want [gnome kde5]", names)
	}
}

func TestGsettingsWithoutSessionIsNotABackend(t *testing.T) {
	setProbe(t,
		[]string{"gsettings", "kwriteconfig5", "kreadconfig5"},
		map[string]error{
			// The exact failure an SSH login or a container gives: the binary
			// runs, the schema cannot be reached.
			"gsettings":    errors.New("dconf-service: cannot autolaunch"),
			"kreadconfig5": nil,
		})
	got := usableBackends()
	for _, b := range got {
		if b.name == "gnome" {
			t.Fatal("a gsettings that cannot answer must not be offered")
		}
	}
}

func TestKDEProbeReadsTheRealFile(t *testing.T) {
	var asked []string
	prevProbe, prevFind := probeRun, findBinary
	probeRun = func(name string, args ...string) error {
		asked = append(asked, name+" "+strings.Join(args, " "))
		return nil
	}
	findBinary = func(string) bool { return true }
	t.Cleanup(func() { probeRun, findBinary = prevProbe, prevFind })

	backends := usableBackends()
	if len(backends) == 0 {
		t.Fatal("everything present should answer")
	}
	sawDefault := false
	for _, call := range asked {
		if strings.Contains(call, "--default") && strings.Contains(call, "ProxyType") {
			sawDefault = true
		}
	}
	// A machine that has KDE's tools but never opened its proxy settings has no
	// kioslaverc yet; the probe passes an explicit default so "no key" is not
	// mistaken for a broken backend.
	if !sawDefault {
		t.Fatalf("the KDE probe must read ProxyType with a default, got %v", asked)
	}
}

func TestBareWindowManagerHasNoTargets(t *testing.T) {
	setProbe(t, nil, nil)
	if _, err := (linuxStore{}).Targets(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

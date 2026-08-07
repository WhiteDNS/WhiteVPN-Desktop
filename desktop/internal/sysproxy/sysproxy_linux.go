//go:build linux

package sysproxy

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Linux has no system proxy setting. It has desktop-environment settings, and
// which one matters depends on what the user is running.
//
// GNOME — and everything built on its schemas: COSMIC, Cinnamon, Budgie, MATE —
// keeps it in gsettings. KDE keeps it in kioslaverc and expects to be told when
// it changes. A bare window manager keeps it nowhere at all, and there the
// honest answer is that this cannot be done.
//
// Both are written when both are present rather than picking one from
// XDG_CURRENT_DESKTOP. The report that prompted this was a Pop!_OS machine
// running KDE — GNOME's schemas installed, KDE's session in front — and reading
// one variable would have configured the half the user was not looking at.
//
// What this cannot do is make it apply to everything. These are preferences that
// well-behaved programs read; a program that ignores them is not reached by
// anything short of a tunnel. Callers should say that rather than promise more.

// backend is one place Linux keeps the setting.
type backend struct {
	name    string
	binary  string
	present bool
}

func availableBackends() []backend {
	backends := []backend{
		{name: "gsettings", binary: gsettingsBinary},
		// KDE 6 first: a machine with both has moved on, and writing the old one
		// there configures a file nothing reads.
		{name: "kde", binary: "kwriteconfig6"},
		{name: "kde", binary: "kwriteconfig5"},
	}
	found := make([]backend, 0, len(backends))
	seen := map[string]bool{}
	for _, candidate := range backends {
		if seen[candidate.name] {
			continue
		}
		if _, err := exec.LookPath(candidate.binary); err != nil {
			continue
		}
		candidate.present = true
		seen[candidate.name] = true
		found = append(found, candidate)
	}
	return found
}

// ErrUnsupported is returned when nothing on this machine knows what a proxy
// setting is — a bare window manager, or a session with neither toolkit.
var ErrUnsupported = errors.New("sysproxy: no desktop proxy setting found (this needs GNOME's gsettings or KDE's kwriteconfig)")

// Current reads what is configured now, from the first backend that answers.
func Current() (State, error) {
	backends := availableBackends()
	if len(backends) == 0 {
		return State{}, ErrUnsupported
	}
	var firstErr error
	for _, b := range backends {
		state, err := readBackend(b)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return state, nil
	}
	return State{}, firstErr
}

// Apply writes the state to every backend this machine has.
func Apply(state State) error {
	backends := availableBackends()
	if len(backends) == 0 {
		return ErrUnsupported
	}
	var firstErr error
	applied := 0
	for _, b := range backends {
		if err := writeBackend(b, state); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		applied++
	}
	if applied == 0 {
		return firstErr
	}
	// One backend refusing while another took it is not a failure: the machine
	// is pointed at the proxy, which is what was asked for.
	return nil
}

// Pointing is the state that sends traffic through endpoint.
func Pointing(endpoint string) (State, error) {
	host, port := splitProxyEndpoint(endpoint)
	if host == "" || port <= 0 {
		return State{}, fmt.Errorf("sysproxy: %q is not a host:port", endpoint)
	}
	return State{Enabled: true, Server: endpoint, Override: DefaultBypass}, nil
}

// Verify reads the settings back and reports whether they took.
func Verify(want State) error {
	got, err := Current()
	if err != nil {
		return err
	}
	if !got.SameAs(want) {
		return fmt.Errorf("sysproxy: the desktop did not keep the settings (wanted %q, found %q)", want.Server, got.Server)
	}
	return nil
}

func readBackend(b backend) (State, error) {
	if b.name == "gsettings" {
		return readGnome()
	}
	return readKDE()
}

func writeBackend(b backend, state State) error {
	if b.name == "gsettings" {
		return writeGnome(state)
	}
	return writeKDE(b.binary, state)
}

// --- GNOME -----------------------------------------------------------------

func readGnome() (State, error) {
	mode, err := gsettingsGet(gnomeProxySchema, "mode")
	if err != nil {
		return State{}, err
	}
	host, _ := gsettingsGet(gnomeProxySchema+".http", "host")
	port, _ := gsettingsGet(gnomeProxySchema+".http", "port")
	ignore, _ := gsettingsGet(gnomeProxySchema, "ignore-hosts")
	return parseGnomeState(mode, host, port, ignore), nil
}

func writeGnome(state State) error {
	for _, args := range gnomeApplyArgs(state) {
		if output, err := exec.Command(gsettingsBinary, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("sysproxy: gsettings %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func gsettingsGet(schema, key string) (string, error) {
	output, err := exec.Command(gsettingsBinary, "get", schema, key).Output()
	if err != nil {
		return "", fmt.Errorf("sysproxy: gsettings get %s %s: %w", schema, key, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// --- KDE -------------------------------------------------------------------

func readKDE() (State, error) {
	reader := "kreadconfig6"
	if _, err := exec.LookPath(reader); err != nil {
		reader = "kreadconfig5"
		if _, err := exec.LookPath(reader); err != nil {
			return State{}, fmt.Errorf("sysproxy: no kreadconfig to read KDE's settings with")
		}
	}
	get := func(key string) string {
		output, err := exec.Command(reader, "--file", kdeProxyConfigFile, "--group", kdeProxyGroup, "--key", key).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(output))
	}
	return parseKDEState(get("ProxyType"), get("httpProxy"), get("NoProxyFor")), nil
}

func writeKDE(binary string, state State) error {
	for key, value := range kdeApplyEntries(state) {
		args := []string{"--file", kdeProxyConfigFile, "--group", kdeProxyGroup, "--key", key, value}
		if output, err := exec.Command(binary, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("sysproxy: %s %s: %w: %s", binary, key, err, strings.TrimSpace(string(output)))
		}
	}
	// Written settings are not read settings: running KDE programs keep the old
	// ones until they are told. Best effort — the file is correct either way and
	// a new program will pick it up.
	_ = exec.Command("dbus-send", "--type=signal", "/KIO/Scheduler",
		"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:").Run()
	return nil
}

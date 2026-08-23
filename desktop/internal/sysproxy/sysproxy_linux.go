//go:build linux

package sysproxy

import (
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

// Current reads what is configured now, from the first backend that answers.
func Current() (State, error) {
	for _, b := range usableBackends() {
		state, err := readBackend(b)
		if err != nil {
			continue
		}
		return state, nil
	}
	return State{}, ErrUnsupported
}

// Apply writes the state to every backend this machine has.
func Apply(state State) error {
	backends := usableBackends()
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
	if b.name == "gnome" {
		return readGnome()
	}
	return readKDE(b.reader)
}

func writeBackend(b backend, state State) error {
	if b.name == "gnome" {
		return writeGnome(state)
	}
	return writeKDE(b.writer, state)
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

func readKDE(reader string) (State, error) {
	get := func(key string) string {
		output, err := exec.Command(reader, "--file", kdeProxyConfigFile, "--group", kdeProxyGroup,
			"--key", key, "--default", "").Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(output))
	}
	return parseKDEState(get("ProxyType"), get("httpProxy"), get("NoProxyFor")), nil
}

func writeKDE(writer string, state State) error {
	for key, value := range kdeApplyEntries(state) {
		args := []string{"--file", kdeProxyConfigFile, "--group", kdeProxyGroup, "--key", key, value}
		if output, err := exec.Command(writer, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("sysproxy: %s %s: %w: %s", writer, key, err, strings.TrimSpace(string(output)))
		}
	}
	// Written settings are not read settings: running KDE programs keep the old
	// ones until they are told. Best effort — the file is correct either way and
	// a new program will pick it up.
	_ = exec.Command("dbus-send", "--type=signal", "/KIO/Scheduler",
		"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:").Run()
	return nil
}

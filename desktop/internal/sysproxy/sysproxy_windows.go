//go:build windows

package sysproxy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The per-user WinINET settings. HKCU, not HKLM: this is one user's browsing
// configuration, and changing it needs no elevation — which matters, because
// the app runs unelevated in proxy mode.
const internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// Current reads what the machine's proxy settings are now.
func Current() (State, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return State{}, fmt.Errorf("sysproxy: open settings: %w", err)
	}
	defer key.Close()

	var state State
	// Every value here is optional: a machine that has never had a proxy has
	// none of them, and that is a valid state to restore to.
	if enabled, _, err := key.GetIntegerValue("ProxyEnable"); err == nil {
		state.Enabled = enabled != 0
	}
	// WinINET's own answer wins over the shim's, because it is the one that
	// decides whether traffic goes through a proxy. They disagree exactly when
	// something has written the shim without going through the API — which is
	// the bug this package used to have.
	if flags, err := perConnectionFlags(); err == nil {
		state.Flags = flags
		state.Enabled = flags&proxyTypeProxy != 0
	}
	if server, _, err := key.GetStringValue("ProxyServer"); err == nil {
		state.Server = server
	}
	if override, _, err := key.GetStringValue("ProxyOverride"); err == nil {
		state.Override = override
	}
	return state, nil
}

// Apply changes the machine's proxy settings.
//
// Through WinINET first, because that is what browsers read, and only then the
// registry shim — which the API also updates, but some software reads it
// directly and a value left behind by an older write would contradict what was
// just set.
func Apply(state State) error {
	if err := applyPerConnection(state); err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open settings: %w", err)
	}
	defer key.Close()

	enabled := uint32(0)
	if state.Enabled {
		enabled = 1
	}
	if err := key.SetDWordValue("ProxyEnable", enabled); err != nil {
		return fmt.Errorf("sysproxy: set ProxyEnable: %w", err)
	}
	// A disabled proxy keeps its address: that is how Windows itself leaves it,
	// and blanking it would lose a setting the user may have put there.
	if err := setOrDelete(key, "ProxyServer", state.Server); err != nil {
		return err
	}
	if err := setOrDelete(key, "ProxyOverride", state.Override); err != nil {
		return err
	}
	return notify()
}

// Pointing is the state that points the machine at endpoint.
//
// The caller composes it, saves what Current returns, and only then calls
// Apply. That order is deliberate and was wrong once: writing the registry
// before recording what was there means a failure between the two leaves a
// machine pointed at this app's proxy with nothing on disk saying what it used
// to be — which after the app exits is not a broken VPN but a broken internet
// connection.
func Pointing(endpoint string) (State, error) {
	if strings.TrimSpace(endpoint) == "" {
		return State{}, fmt.Errorf("sysproxy: no proxy address to set")
	}
	current, err := Current()
	if err != nil {
		return State{}, err
	}
	// The flags come from what is already configured, so enabling the proxy
	// adds to them rather than replacing them.
	return State{Enabled: true, Server: endpoint, Override: DefaultBypass, Flags: current.Flags}, nil
}

// Verify reads the settings back and reports whether they are what was asked
// for.
//
// Worth the second read: the registry write can succeed against a key another
// program is also writing, and a badge claiming the machine is using this proxy
// when it is not is worse than no badge at all.
func Verify(want State) error {
	// Asked of WinINET, not of the registry: a read-back that goes to the same
	// place the write went proves only that the write happened, and this has to
	// prove the machine will use it.
	enabled, err := perConnectionProxyEnabled()
	if err != nil {
		return err
	}
	if enabled != want.Enabled {
		return fmt.Errorf("sysproxy: the settings were written but the system is still set to %s",
			map[bool]string{true: "use a proxy", false: "connect directly"}[enabled])
	}
	got, err := Current()
	if err != nil {
		return err
	}
	if !got.SameAs(want) {
		return fmt.Errorf("sysproxy: the settings did not stick — asked for %q (enabled=%t), found %q (enabled=%t)",
			want.Server, want.Enabled, got.Server, got.Enabled)
	}
	return nil
}

func setOrDelete(key registry.Key, name, value string) error {
	if value == "" {
		if err := key.DeleteValue(name); err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("sysproxy: clear %s: %w", name, err)
		}
		return nil
	}
	if err := key.SetStringValue(name, value); err != nil {
		return fmt.Errorf("sysproxy: set %s: %w", name, err)
	}
	return nil
}

// The registry write alone changes nothing for anything already running: WinINET
// caches the settings, so applications keep using the old ones until they are
// told. These two options are the telling.
const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet               = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
)

func notify() error {
	for _, option := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		// A zero return means the notification failed. The settings are written
		// either way and anything started afterwards reads them, so this is
		// reported rather than treated as the write having failed.
		if result, _, err := procInternetSetOption.Call(0, option, 0, 0); result == 0 {
			return fmt.Errorf("sysproxy: the system did not accept the change notification: %w", err)
		}
	}
	return nil
}

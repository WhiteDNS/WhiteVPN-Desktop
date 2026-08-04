package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
)

// The engine.
//
// mihomo is what WhiteVPN for Android runs, and so it is what this runs: an app
// that shares a name, a subscription and a backend with the phone should not
// behave differently from it.
//
// The Xray path it replaced is still reachable with WHITEVPN_ENGINE=xray. It is
// kept for a while because when someone reports that a server works on one and
// not the other, being able to switch is how that gets diagnosed rather than
// argued about.
const engineEnvVar = "WHITEVPN_ENGINE"

func mihomoEngineSelected() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv(engineEnvVar)), "xray")
}

// mihomoState is the running mihomo session, if there is one.
type mihomoState struct {
	mu      sync.Mutex
	session *session.Session
}

func (m *mihomoState) swap(next *session.Session) *session.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.session
	m.session = next
	return previous
}

func (m *mihomoState) current() *session.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.session
}

// startWhiteDNSVPNWithMihomo connects using the engine the phone app uses.
//
// It reports connected only after session.Connect has proved a request travels
// through the proxy, so the status the user sees is not the engine's opinion of
// itself.
func (a *App) startWhiteDNSVPNWithMihomo() (model.AppState, error) {
	ctx := context.Background()

	corePath, err := findMihomoCore()
	if err != nil {
		a.handleRuntimeState(model.RuntimeFailed, err.Error())
		return a.GetAppState(), err
	}

	a.setMihomoRuntimeType()
	a.handleRuntimeState(model.RuntimeConnecting, "Fetching subscription")

	raw, err := fetchWhiteDNSVPNSubscriptionDocument(ctx)
	if err != nil {
		a.handleRuntimeState(model.RuntimeFailed, fmt.Sprintf("Subscription unavailable: %v", err))
		return a.GetAppState(), err
	}
	subscription, err := decryptWhiteDNSVPNSubscription(raw, whiteDNSVPNSubscriptionKey)
	if err != nil {
		a.handleRuntimeState(model.RuntimeFailed, fmt.Sprintf("Subscription unreadable: %v", err))
		return a.GetAppState(), err
	}

	homeDir := filepath.Join(a.configDir, "mihomo")
	a.handleRuntimeState(model.RuntimeConnecting, "Starting engine")

	a.mu.Lock()
	settings := model.NormalizeWhiteVPNSettings(a.state.WhiteVPN)
	a.mu.Unlock()

	connected, err := session.Connect(ctx, session.Options{
		CorePath:     corePath,
		HomeDir:      homeDir,
		Subscription: subscription,
		DNSPrivacy:   dnsPrivacyMode(settings.DNSPrivacy.Mode),
		DoHURL:       settings.DNSPrivacy.DoHURL,
		DoTEndpoint:  settings.DNSPrivacy.DoTEndpoint,
		Tun:          tunOptionsFor(settings),
		CoreStdout:   mihomoLogWriter{app: a},
		CoreStderr:   mihomoLogWriter{app: a},
	})
	if err != nil {
		a.handleRuntimeState(model.RuntimeFailed, err.Error())
		return a.GetAppState(), err
	}

	if previous := a.mihomo.swap(connected); previous != nil {
		_ = previous.Close()
	}

	a.mu.Lock()
	a.state.Runtime.ListenIP = "127.0.0.1"
	a.state.Runtime.ListenPort = connected.MixedPort()
	a.state.Runtime.ProxyProtocol = "mixed"
	a.state.Runtime.LocalProxyIP = "127.0.0.1"
	a.mu.Unlock()

	a.appendRuntimeLog(fmt.Sprintf(
		"mihomo connected: %d nodes available, using %q, health %d",
		connected.ProxyCount(), connected.Selected(), connected.HealthStatus(),
	))
	a.handleRuntimeState(model.RuntimeConnected, fmt.Sprintf("Proxy listening on 127.0.0.1:%d", connected.MixedPort()))
	return a.GetAppState(), nil
}

// stopMihomo shuts the session down. It reports whether there was one, so the
// caller knows whether the Xray path still needs stopping.
func (a *App) stopMihomo() bool {
	current := a.mihomo.swap(nil)
	if current == nil {
		return false
	}
	_ = current.Close()
	a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	return true
}

func (a *App) setMihomoRuntimeType() {
	a.mu.Lock()
	a.state.Runtime.RuntimeType = model.RuntimeTypeV2Ray
	a.mu.Unlock()
}

func (a *App) appendRuntimeLog(line string) {
	a.mu.Lock()
	a.appendRuntimeLogLocked(model.RuntimeTypeV2Ray, line)
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	a.emit("runtime:state", runtimeState)
}

// mihomoLogWriter forwards the engine's own output into the app's log view.
// Startup failures are often printed there and nowhere else.
type mihomoLogWriter struct{ app *App }

func (w mihomoLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			w.app.appendRuntimeLog(trimmed)
		}
	}
	return len(p), nil
}

// findMihomoCore locates the engine binary. `make mihomo-core` puts it in
// cores/ beside the Xray one.
func findMihomoCore() (string, error) {
	name := fmt.Sprintf("mihomo-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if override := strings.TrimSpace(os.Getenv("WHITEVPN_MIHOMO_BIN")); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override, nil
		}
		return "", fmt.Errorf("WHITEVPN_MIHOMO_BIN points at %s, which is not there", override)
	}
	if dir := findXrayCoresDir(); dir != "" {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("the mihomo engine (%s) is not built; run `make mihomo-core`", name)
}

// dnsPrivacyMode maps the stored setting onto the engine's.
func dnsPrivacyMode(mode string) mihomoconf.DNSPrivacyMode {
	switch mode {
	case model.DNSPrivacyDoH:
		return mihomoconf.DNSOverHTTPS
	case model.DNSPrivacyDoT:
		return mihomoconf.DNSOverTLS
	default:
		return mihomoconf.DNSAutomatic
	}
}

// tunOptionsFor turns the tunnel setting into engine options.
//
// Turning the tunnel on is attempted even though creating its adapter needs
// Administrator, which this process does not have until the privileged helper
// exists. Attempting and failing is better than refusing: the engine will report
// itself started either way, and the health check is what catches the difference,
// so the user is told the connection carried no traffic rather than told nothing
// and left with a switch that does nothing.
func tunOptionsFor(settings model.WhiteVPNSettings) mihomoconf.TunOptions {
	if !settings.TunEnabled {
		return mihomoconf.TunOptions{Enabled: false}
	}
	return mihomoconf.DefaultTunOptions()
}

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

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
	ctx, cancel := a.beginConnect()
	defer cancel()

	corePath, err := findMihomoCore()
	if err != nil {
		a.reportConnectFailure(ctx, err.Error())
		return a.GetAppState(), err
	}

	a.setMihomoRuntimeType()
	a.handleRuntimeState(model.RuntimeConnecting, "Fetching subscription")

	raw, err := fetchWhiteDNSVPNSubscriptionDocument(ctx)
	if err != nil {
		a.reportConnectFailure(ctx, fmt.Sprintf("Subscription unavailable: %v", err))
		return a.GetAppState(), err
	}
	subscription, err := decryptWhiteDNSVPNSubscription(raw, whiteDNSVPNSubscriptionKey)
	if err != nil {
		a.reportConnectFailure(ctx, fmt.Sprintf("Subscription unreadable: %v", err))
		return a.GetAppState(), err
	}

	homeDir := filepath.Join(a.configDir, "mihomo")

	a.mu.Lock()
	settings := model.NormalizeWhiteVPNSettings(a.state.WhiteVPN)
	a.mu.Unlock()

	// The dashboard's choices are applied here, against the catalogue this
	// attempt is about to use, so a node that has left the catalogue is caught
	// now rather than by the engine.
	nodes, err := whiteVPNNodesFromSubscription(subscription)
	if err != nil {
		a.reportConnectFailure(ctx, err.Error())
		return a.GetAppState(), err
	}
	a.storeWhiteVPNNodes(nodes, time.Now().UTC())
	prefer := preferredNodeNames(nodes, settings)
	if len(prefer) == 0 && selectionIsNarrowed(settings) {
		err := fmt.Errorf("no node matches the chosen location or connection; change it on the VPN page")
		a.reportConnectFailure(ctx, err.Error())
		return a.GetAppState(), err
	}

	a.handleRuntimeState(model.RuntimeConnecting, "Starting engine")

	connected, err := session.Connect(ctx, session.Options{
		CorePath:     corePath,
		HomeDir:      homeDir,
		Subscription: subscription,
		Prefer:       prefer,
		DNSPrivacy:   dnsPrivacyMode(settings.DNSPrivacy.Mode),
		DoHURL:       settings.DNSPrivacy.DoHURL,
		DoTEndpoint:  settings.DNSPrivacy.DoTEndpoint,
		Tun:          tunOptionsFor(settings),
		CoreStdout:   mihomoLogWriter{app: a},
		CoreStderr:   mihomoLogWriter{app: a},
	})
	if err != nil {
		a.reportConnectFailure(ctx, err.Error())
		return a.GetAppState(), err
	}

	if !a.adoptSession(ctx, connected) {
		// Stopped while the last steps were running. Nothing may be left
		// running behind an interface that says disconnected.
		_ = connected.Close()
		a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
		return a.GetAppState(), nil
	}

	a.mu.Lock()
	a.state.Runtime.ListenIP = "127.0.0.1"
	a.state.Runtime.ListenPort = connected.MixedPort()
	a.state.Runtime.ProxyProtocol = "mixed"
	a.state.Runtime.LocalProxyIP = "127.0.0.1"
	a.mu.Unlock()
	a.recordConnectedNode(connected.Selected())

	a.appendRuntimeLog(fmt.Sprintf(
		"mihomo connected: %d nodes available, using %q, health %d",
		connected.ProxyCount(), connected.Selected(), connected.HealthStatus(),
	))
	a.handleRuntimeState(model.RuntimeConnected, fmt.Sprintf("Proxy listening on 127.0.0.1:%d", connected.MixedPort()))
	a.resolveExitCountry()
	return a.GetAppState(), nil
}

// recordConnectedNode notes which node is carrying traffic and where its own
// name says it is. That answer costs nothing and is right immediately, which is
// what the interface needs while the measured one is still being fetched.
func (a *App) recordConnectedNode(name string) {
	a.mu.Lock()
	a.state.Runtime.NodeName = name
	a.state.Runtime.NodeCountryCode = countryCodeFromNodeName(name)
	// The measurement belongs to the node that has just been left.
	a.state.Runtime.PublicProxyIP = ""
	a.state.Runtime.ExitCountryCode = ""
	a.state.Runtime.ExitChecked = false
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	// The measurement is cached under the local proxy address, which does not
	// change when the node behind it does. Without this, switching node keeps
	// reporting the country of the node before it.
	a.clearProxyCountryCache()
	a.emit("runtime:state", runtimeState)
}

// resolveExitCountry finds out where traffic actually leaves from, by asking
// through the proxy itself.
//
// It runs in the background because it is a network round trip and the
// connection is already up without it; and it is worth doing at all because the
// flag in a node's name is that node's claim, while this is a measurement. When
// the two disagree the interface shows this one.
func (a *App) resolveExitCountry() {
	go func() {
		result, err := a.LookupProxyCountry()

		a.mu.Lock()
		if a.state.Runtime.Status != model.RuntimeConnected {
			// Disconnected while the lookup was in flight; the answer is about
			// a connection that no longer exists.
			a.mu.Unlock()
			return
		}
		a.state.Runtime.ExitChecked = true
		if err == nil && result.OK {
			a.state.Runtime.PublicProxyIP = result.IP
			a.state.Runtime.ExitCountryCode = strings.ToUpper(strings.TrimSpace(result.CountryCode))
		}
		runtimeState := a.state.Runtime
		a.mu.Unlock()
		a.emit("runtime:state", runtimeState)
	}()
}

// Cancelling a connect.
//
// Connecting takes as long as it takes: a subscription fetch, then up to five
// nodes each given a health budget. A control that offers to stop that has to
// actually stop it, so the connect runs under a context the stop can cancel,
// and every step of session.Connect honours it — including the cleanup that
// stops an engine already spawned.

// beginConnect starts a cancellable attempt, superseding any attempt still
// registered.
func (a *App) beginConnect() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	a.connectMu.Lock()
	previous := a.connectCancel
	a.connectCancel = cancel
	a.connectMu.Unlock()
	if previous != nil {
		previous()
	}
	return ctx, cancel
}

// cancelConnect asks an in-flight connect to unwind. It reports whether there
// was one.
func (a *App) cancelConnect() bool {
	a.connectMu.Lock()
	cancel := a.connectCancel
	a.connectCancel = nil
	a.connectMu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

// adoptSession takes ownership of a freshly connected session, unless the
// attempt was cancelled first. Deciding that under the same lock cancelConnect
// takes is what stops a stop and a connect that finish together from leaving an
// engine running with nothing pointing at it.
//
// It reports whether the session was adopted; an unadopted one is the caller's
// to close.
func (a *App) adoptSession(ctx context.Context, next *session.Session) bool {
	a.connectMu.Lock()
	if ctx.Err() != nil {
		a.connectMu.Unlock()
		return false
	}
	a.connectCancel = nil
	previous := a.mihomo.swap(next)
	a.connectMu.Unlock()

	// Closing takes as long as stopping an engine takes, and a stop waiting on
	// this lock would wait for it too.
	if previous != nil {
		_ = previous.Close()
	}
	return true
}

// reportConnectFailure records why a connect ended. A connect the user stopped
// is not a failure: it must not leave an error on screen and a Retry button
// where a disconnect was asked for.
func (a *App) reportConnectFailure(ctx context.Context, message string) {
	if ctx.Err() != nil {
		a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
		return
	}
	a.handleRuntimeState(model.RuntimeFailed, message)
}

// stopMihomo shuts the session down. It reports whether there was one, so the
// caller knows whether the Xray path still needs stopping.
func (a *App) stopMihomo() bool {
	current := a.mihomo.swap(nil)
	if current == nil {
		return false
	}
	_ = current.Close()
	a.mu.Lock()
	a.state.Runtime.Engine = ""
	a.mu.Unlock()
	a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	return true
}

// EngineMihomo marks a runtime as belonging to the mihomo session.
const EngineMihomo = "mihomo"

func (a *App) setMihomoRuntimeType() {
	a.mu.Lock()
	a.state.Runtime.RuntimeType = model.RuntimeTypeV2Ray
	a.state.Runtime.Engine = EngineMihomo
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

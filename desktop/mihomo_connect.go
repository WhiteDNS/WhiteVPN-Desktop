package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
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
// behave differently from it. It is the only engine now; the Xray path it
// replaced, and the environment variable that chose between them, were removed
// once it became clear that a second path meant features written against it
// were invisible in the app that ships.

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

	subscription, err := a.subscriptionBody(ctx)
	if err != nil {
		a.reportConnectFailure(ctx, err.Error())
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
	a.storeWhiteVPNNodes(a.selectedSubscriptionID(), nodes, time.Now().UTC())
	prefer := preferredNodeNames(nodes, settings)
	if len(prefer) == 0 && selectionIsNarrowed(settings) {
		err := fmt.Errorf("no node matches the chosen location or connection; change it on the VPN page")
		a.reportConnectFailure(ctx, err.Error())
		return a.GetAppState(), err
	}

	// IP fronting. Until now this setting was read only by the Xray path, which
	// is not the engine this app runs, so it was a control that changed nothing.
	frontingIP := ""
	if len(settings.FrontingIPs) > 0 {
		frontingIP = settings.FrontingIPs[0]
		a.appendRuntimeLog(fmt.Sprintf("fronting through %s", frontingIP))
	}

	a.handleRuntimeState(model.RuntimeConnecting, "Starting engine")

	mixedPort, err := chooseProxyPort(settings)
	if err != nil {
		a.reportConnectFailure(ctx, err.Error())
		return a.GetAppState(), err
	}

	connected, err := session.Connect(ctx, session.Options{
		CorePath:     corePath,
		HomeDir:      homeDir,
		MixedPort:    mixedPort,
		AllowLAN:     settings.AllowLAN,
		Subscription: subscription,
		Prefer:       prefer,
		// Nodes the user hid never reach the configuration, so the engine cannot
		// choose one on Automatic. Hidden from the list but still connectable
		// would be the worst of both.
		Exclude:     a.hiddenNodeNames(a.selectedSubscriptionID()),
		SplitTunnel: splitTunnelFor(settings),
		// The fourth control that was stored and never read. It refuses a node
		// whose certificates do not verify through the tunnel — a connection
		// that carries traffic while being read is the failure it exists for.
		VerifyTLSIntegrity: settings.TLSIntegrityEnabled,
		Noise:              amneziaNoiseFor(settings),
		FrontingIP:         frontingIP,
		DNSPrivacy:         dnsPrivacyMode(settings.DNSPrivacy.Mode),
		DoHURL:             settings.DNSPrivacy.DoHURL,
		DoTEndpoint:        settings.DNSPrivacy.DoTEndpoint,
		Tun:                tunOptionsFor(settings),
		CoreStdout:         mihomoLogWriter{app: a},
		CoreStderr:         mihomoLogWriter{app: a},
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

	// Shared over the network, the address another device needs is this machine's
	// on the LAN. PublicProxyIP is the field for it — documented as exactly that
	// and never filled in until now — and the dashboard already prefers it, so
	// what gets copied off the screen is what a phone can actually be pointed at.
	sharedAddress := ""
	if settings.AllowLAN {
		if sharedAddress = lanAddress(); sharedAddress != "" {
			a.appendRuntimeLog(fmt.Sprintf(
				"shared on the network: other devices can use %s:%d", sharedAddress, connected.MixedPort()))
		} else {
			// Listening on every interface and not one of them reachable. Said
			// plainly rather than leaving a switch that appears to have worked.
			a.appendRuntimeLog("sharing is on, but this machine has no local network address to share on")
		}
	}

	a.mu.Lock()
	a.state.Runtime.ListenIP = "127.0.0.1"
	a.state.Runtime.ListenPort = connected.MixedPort()
	a.state.Runtime.ProxyProtocol = "mixed"
	a.state.Runtime.LocalProxyIP = "127.0.0.1"
	a.state.Runtime.PublicProxyIP = sharedAddress
	a.mu.Unlock()
	a.recordConnectedNode(connected.Selected())
	if proxyOnly(settings) {
		// Nothing on the machine has been redirected, which is the point: the
		// engine listens and the user points one program at it. Said plainly,
		// because a connection that changed nothing otherwise looks like one
		// that did not work.
		a.appendRuntimeLog(fmt.Sprintf(
			"proxy-only: nothing on this machine was redirected — point your programs at 127.0.0.1:%d (HTTP or SOCKS5)",
			connected.MixedPort()))
	}
	if !settings.TunEnabled && settings.SetSystemProxy {
		// Proxy mode: without this the engine listens and nothing on the
		// machine is talking to it. With the tunnel up the routing is the
		// tunnel's job and a proxy as well would be one hop too many.
		//
		// SetSystemProxy is checked because it had been stored, defaulted and
		// logged since this path was written, and never once read — so turning
		// the tunnel off silently reconfigured the whole machine, and there was
		// no way to ask for the engine to just listen.
		if err := a.captureSystemProxy(connected.MixedPort()); err != nil {
			// Not fatal. The connection is up and the proxy is listening; what
			// failed is pointing the machine at it, and that is something a user
			// can do by hand. Tearing down a working connection over it left the
			// app with no usable mode at all on a desktop this cannot configure —
			// which is what a Linux user got, having been told his connection had
			// failed when it had not.
			a.appendRuntimeLog(fmt.Sprintf("could not configure the system proxy: %v", err))
			a.appendRuntimeLog(fmt.Sprintf(
				"the connection is up — point your programs at 127.0.0.1:%d, or use tunnel mode", connected.MixedPort()))
			a.emit("runtime:notice", fmt.Sprintf(
				"Connected, but this desktop's proxy settings could not be changed. Set your browser's proxy to 127.0.0.1:%d.",
				connected.MixedPort()))
		}
	}

	if connected.Automatic() {
		a.appendRuntimeLog(fmt.Sprintf(
			"mihomo connected: %d nodes available, %d answered a delay test, engine picked %q, health %d",
			connected.ProxyCount(), connected.Seeded(), connected.Selected(), connected.HealthStatus(),
		))
	} else {
		a.appendRuntimeLog(fmt.Sprintf(
			"mihomo connected: %d nodes available, using %q, health %d",
			connected.ProxyCount(), connected.Selected(), connected.HealthStatus(),
		))
	}
	if err := connected.TunnelUnverified(); err != nil {
		// The tunnel is up but nothing confirmed its routes, so the log says so
		// rather than leaving the impression it was checked.
		a.appendRuntimeLog(fmt.Sprintf("the tunnel is running but was not verified: %v", err))
	}
	a.handleRuntimeState(model.RuntimeConnected, fmt.Sprintf("Proxy listening on 127.0.0.1:%d", connected.MixedPort()))
	a.resolveExitCountry()
	a.sampleTraffic(connected)
	a.watchHealth(connected)
	a.retryBlockedSubscriptions()
	return a.GetAppState(), nil
}

// sampleTraffic keeps the dashboard's download and upload counters moving.
//
// The engine counts its own traffic; nothing else on this machine can, now that
// the runtime manager and its sampler have gone with the Xray path. Until this
// was wired the two tiles sat at zero through a working connection, which reads
// as a connection carrying nothing.
func (a *App) sampleTraffic(current *session.Session) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// The session this sampler belongs to may have been replaced or
			// stopped; its successor starts its own.
			if a.mihomo.current() != current {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			upRate, downRate, rateErr := current.Engine().TrafficRate(ctx, false)
			upTotal, downTotal, totalErr := current.Engine().TrafficTotal(ctx, false)
			cancel()
			if rateErr != nil || totalErr != nil {
				// A dead engine ends the sampler; a hiccup does not.
				select {
				case <-current.Engine().Done():
					return
				default:
					continue
				}
			}
			a.handleStats(model.TrafficStats{
				DownloadBytes:               downTotal,
				UploadBytes:                 upTotal,
				DownloadSpeedBytesPerSecond: downRate,
				UploadSpeedBytesPerSecond:   upRate,
				TotalDataUsageBytes:         upTotal + downTotal,
			})
		}
	}()
}

// recordConnectedNode notes which node is carrying traffic and where its own
// name says it is. That answer costs nothing and is right immediately, which is
// what the interface needs while the measured one is still being fetched.
func (a *App) recordConnectedNode(name string) {
	a.mu.Lock()
	a.state.Runtime.NodeName = name
	a.state.Runtime.NodeCountryCode = countryCodeFromNodeName(name)
	// The measurement belongs to the node that has just been left.
	a.state.Runtime.ExitIP = ""
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
			a.state.Runtime.ExitIP = result.IP
			a.state.Runtime.ExitCountryCode = strings.ToUpper(strings.TrimSpace(result.CountryCode))
		}
		runtimeState := a.state.Runtime
		a.mu.Unlock()
		if err != nil {
			// Worth a line: this is a request through the proxy, so its failure
			// says something about the connection and not only about the badge.
			a.appendRuntimeLog(fmt.Sprintf("could not measure where traffic leaves from: %v", err))
		} else if !result.OK {
			a.appendRuntimeLog("the exit check returned nothing recognisable")
		}
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
	// Before the status changes, so the machine is never pointed at a proxy
	// that has already stopped listening.
	a.restoreSystemProxy()
	a.mu.Lock()
	a.state.Runtime.Engine = ""
	a.mu.Unlock()
	a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	return true
}

// chooseProxyPort is the port the engine will listen on: the usual one if it is
// free, otherwise any port that is.
//
// The engine used to take 2080 unconditionally. When something else already
// holds it — another VPN client, a previous instance that has not let go — the
// listener does not come up, and the health check then talks to whatever *is*
// on 2080 and reports a healthy connection through someone else's proxy. A port
// this app cannot bind is not a port it can claim.
// chooseProxyPort picks the port the engine's local proxy listens on.
//
// How hard it insists depends on whether anyone outside this app is relying on
// the number. With the tunnel up, or with the machine's proxy settings pointed
// here, nothing the user configured depends on it and any free port will do.
//
// In proxy-only mode the port *is* the interface: it is what somebody typed into
// Telegram or a browser extension, and quietly binding a different one means
// their program stops working days later, in another application, with nothing
// anywhere connecting that to this app. So there it is held, and a port that
// cannot be had is reported instead of worked around.
func chooseProxyPort(settings model.WhiteVPNSettings) (int, error) {
	wanted := settings.ListenPort
	if wanted <= 0 {
		wanted = mihomoconf.DefaultMixedPort
	}

	if proxyOnly(settings) {
		if !portIsFree(wanted) {
			return 0, fmt.Errorf("port %d is already in use by another program — choose a different local proxy port in Settings, or turn the system proxy back on", wanted)
		}
		return wanted, nil
	}

	for _, port := range []int{wanted, 0} {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		bound := listener.Addr().(*net.TCPAddr).Port
		// Released immediately: this was a question, not a reservation. The
		// engine binds it a moment later, and losing that race is a connection
		// that fails loudly rather than one that succeeds through a stranger.
		_ = listener.Close()
		return bound, nil
	}
	return wanted, nil
}

// proxyOnly is the mode where the engine listens and nothing else on the machine
// is touched — no virtual adapter, no change to the machine's proxy settings.
//
// It is the mode for pointing one program at the tunnel: a browser extension, or
// Telegram's proxy field, while everything else goes out normally.
func proxyOnly(settings model.WhiteVPNSettings) bool {
	return !settings.TunEnabled && !settings.SetSystemProxy
}

func portIsFree(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// GetLocalProxyEndpoint is where the engine's local proxy listens, whether or
// not it is running.
//
// The dashboard used to fall back to the listen port on the V2Ray settings
// profile when nothing was connected, which is a field of the removed Xray path
// that nothing reads: it showed 10888 while the engine listened on 2080. A port
// the user is invited to configure their browser with has to be the port
// traffic will actually arrive on.
// It went on to report the default whatever the engine had actually bound,
// which is the same fault in a smaller place: a running session may be on
// another port entirely, and the number offered for someone to configure their
// browser with has to be the one traffic will arrive on.
func (a *App) GetLocalProxyEndpoint() string {
	if current := a.mihomo.current(); current != nil {
		if port := current.MixedPort(); port > 0 {
			return fmt.Sprintf("127.0.0.1:%d", port)
		}
	}

	a.mu.Lock()
	port := model.NormalizeWhiteVPNSettings(a.state.WhiteVPN).ListenPort
	a.mu.Unlock()
	if port <= 0 {
		port = mihomoconf.DefaultMixedPort
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
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
		// The core is launched with elevation on Windows. Only use the copy
		// shipped inside the signed application rather than an environment or
		// working-directory path that another local process could replace.
		return extractEmbeddedCore(name)
	}
	if override := strings.TrimSpace(os.Getenv("WHITEVPN_MIHOMO_BIN")); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override, nil
		}
		return "", fmt.Errorf("WHITEVPN_MIHOMO_BIN points at %s, which is not there", override)
	}
	if dir := findCoresDir(); dir != "" {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	// Nothing beside the app: unpack the copy that travels inside it, so an
	// install is one file rather than a file and a folder that has to stay with
	// it.
	return extractEmbeddedCore(name)
}

// extractEmbeddedCore writes the engine out beside the app's own data, once.
func extractEmbeddedCore(name string) (string, error) {
	raw, err := coreAssets.ReadFile("cores/" + name)
	if err != nil {
		return "", fmt.Errorf("the mihomo engine (%s) is not in this build; run `make mihomo-core`", name)
	}
	dir, err := appConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "cores")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	target := filepath.Join(dir, name)

	// Compare content, not just size: a same-sized replacement must never be
	// reused, especially because this executable is elevated on Windows.
	if err := writeEmbeddedFile(target, raw, 0o755); err != nil {
		return "", fmt.Errorf("unpack the engine: %w", err)
	}
	if runtime.GOOS == "windows" {
		wintun, err := coreAssets.ReadFile("cores/wintun.dll")
		if err != nil {
			return "", fmt.Errorf("the Wintun driver is not in this build: %w", err)
		}
		// The tunnel driver has to sit beside the engine that loads it.
		if err := writeEmbeddedFile(filepath.Join(dir, "wintun.dll"), wintun, 0o644); err != nil {
			return "", fmt.Errorf("unpack the Wintun driver: %w", err)
		}
	}
	return target, nil
}

func writeEmbeddedFile(path string, raw []byte, mode os.FileMode) error {
	matches, err := fileMatches(path, raw)
	if err == nil && matches {
		return nil
	}
	return os.WriteFile(path, raw, mode)
}

func fileMatches(path string, raw []byte) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if info.Size() != int64(len(raw)) {
		return false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}
	expected := sha256.Sum256(raw)
	return string(hash.Sum(nil)) == string(expected[:]), nil
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

// amneziaNoiseFor turns the saved noise setting into the engine's shape.
//
// The third control that was stored and never read. It reaches WireGuard proxies
// and nothing else, which is the line Android draws too, because the noise is
// AmneziaWG's and mihomo has nowhere to put it on a vless or trojan node.
func amneziaNoiseFor(settings model.WhiteVPNSettings) mihomoconf.AmneziaNoise {
	return mihomoconf.AmneziaNoise{
		Enabled: settings.AmneziaNoise.Enabled,
		Count:   settings.AmneziaNoise.Count,
		MinSize: settings.AmneziaNoise.MinSize,
		MaxSize: settings.AmneziaNoise.MaxSize,
	}
}

// splitTunnelFor turns the saved setting into the engine's shape.
//
// This is the wiring that was missing. The setting was stored, validated and
// shown for weeks while nothing outside the model ever read it, so a program
// added to the bypass list went through the tunnel like everything else and the
// site it was meant to reach still saw the VPN. A control that changes nothing
// is worse than one that is absent.
func splitTunnelFor(settings model.WhiteVPNSettings) mihomoconf.SplitTunnel {
	switch settings.SplitTunnel.Mode {
	case model.SplitTunnelBypass:
		return mihomoconf.SplitTunnel{
			Mode:      mihomoconf.SplitTunnelBypass,
			Processes: settings.SplitTunnel.Processes,
		}
	case model.SplitTunnelVPNOnly:
		return mihomoconf.SplitTunnel{
			Mode:      mihomoconf.SplitTunnelOnly,
			Processes: settings.SplitTunnel.Processes,
		}
	default:
		return mihomoconf.SplitTunnel{}
	}
}

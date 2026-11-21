package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/engines"
	"whitevpn-desktop/internal/engines/psiphon"
	"whitevpn-desktop/internal/engines/tor"
	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
	"whitevpn-desktop/internal/sessionmanager"
)

// One line per engine package.
func init() {
	engines.Register(engineprofiles.Psiphon, psiphon.Engine())
	engines.Register(engineprofiles.Tor, torEngine())
}

// torEngine adapts internal/engines/tor to the registry. scripts/build-tor-engine.sh
// stages cores/tor-<goos>-<goarch>/ (tor.exe, lyrebird.exe, conjure-client.exe,
// geoip, geoip6); it is unpacked as one folder because Tor finds its transports
// and geoip files beside tor.exe.
func torEngine() engines.Engine {
	dir := fmt.Sprintf("tor-%s-%s/", runtime.GOOS, runtime.GOARCH)
	return engines.Engine{
		Binaries:  []string{dir + "tor.exe", dir + "lyrebird.exe"},
		Processes: []string{"conjure-client.exe"},
		Start: func(ctx context.Context, opts engines.StartOptions) (engines.Process, error) {
			if opts.Profile.Config.Tor == nil {
				return nil, fmt.Errorf("tor: invalid start options")
			}
			torPath, err := opts.Binary(dir + "tor.exe")
			if err != nil {
				return nil, err
			}
			if _, err := opts.Binary(dir + "lyrebird.exe"); err != nil {
				return nil, err
			}
			for _, optional := range []string{"conjure-client.exe", "geoip", "geoip6"} {
				_, _ = opts.Binary(dir + optional)
			}
			logf := func(format string, args ...any) {
				if opts.Log != nil {
					opts.Log("Tor: " + fmt.Sprintf(format, args...))
				}
			}
			p, err := tor.Start(ctx, tor.Options{TorPath: torPath, PluginDir: filepath.Dir(torPath),
				DataDir: filepath.Join(opts.DataDir, opts.Profile.ID), Config: *opts.Profile.Config.Tor,
				DefaultBridges: tor.DefaultBridges, Logf: logf})
			if err != nil {
				return nil, err // a typed nil *tor.Process must not become a non-nil Process
			}
			return p, nil
		},
	}
}

// Test seams: the fake-engine end-to-end test runs without a Mihomo build.
var (
	engineMihomoCore  = findMihomoCore
	engineStartMihomo = (*App).startManagedMihomo
)

var errSelectedEngineMissing = errors.New("the selected connection engine was deleted; choose a subscription or another engine")

// shippedBinary locates a file shipped in cores/, by its slash-separated path
// there. On Windows only the copy embedded in the signed app is used, as for
// the Mihomo core, unpacked under the same relative path.
func shippedBinary(name string) (string, error) {
	if !fs.ValidPath(name) || name == "." {
		return "", fmt.Errorf("invalid engine binary name")
	}
	if runtime.GOOS != "windows" {
		if dir := findCoresDir(); dir != "" {
			if candidate := filepath.Join(dir, filepath.FromSlash(name)); fileExists(candidate) {
				return candidate, nil
			}
		}
	}
	raw, err := coreAssets.ReadFile("cores/" + name)
	if err != nil {
		return "", fmt.Errorf("%s is not in this build", name)
	}
	dir, err := appConfigDir()
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, "cores", filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	if err := writeEmbeddedFile(target, raw, 0o755); err != nil {
		return "", fmt.Errorf("unpack %s: %w", name, err)
	}
	return target, nil
}

func shippedBinaryPresent(name string) bool {
	if info, err := fs.Stat(coreAssets, "cores/"+name); err == nil && info.Size() > 0 {
		return true
	}
	if runtime.GOOS == "windows" {
		return false
	}
	dir := findCoresDir()
	return dir != "" && fileExists(filepath.Join(dir, filepath.FromSlash(name)))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// engineUnavailable is "" when the kind can run here, else the reason code
// GetEngineAvailability reports (Android EngineNativeAvailability.check).
func (a *App) engineUnavailable(kind engineprofiles.Kind) string {
	if runtime.GOOS != "windows" {
		return "platform-unsupported"
	}
	if _, err := a.engineProfileStore(); err != nil {
		return "credential-vault-unavailable"
	}
	engine, ok := engines.Lookup(kind)
	if !ok {
		return "backend-not-installed"
	}
	for _, name := range engine.Binaries {
		if !shippedBinaryPresent(name) {
			return "binary-missing"
		}
	}
	return ""
}

func (a *App) engineDataDir(kind engineprofiles.Kind) string {
	return filepath.Join(a.configDir, "engines", string(kind))
}

func (a *App) selectedEngineRoute() *engineprofiles.RouteRef {
	a.engineDataMu.RLock()
	defer a.engineDataMu.RUnlock()
	store, err := a.engineProfileStore()
	if err != nil {
		return nil
	}
	if ref := store.Selected(); ref != nil && ref.Kind == "engine" {
		return ref
	}
	return nil
}

func (a *App) ensureRouteChangeAllowed() error {
	if a.mihomo.current() != nil || a.hasManagedOwner() {
		return fmt.Errorf("disconnect before changing the connection: it is running on the current one")
	}
	return nil
}

func (a *App) clearEngineSelection() error {
	if a.selectedEngineRoute() == nil {
		return nil
	}
	if err := a.ensureRouteChangeAllowed(); err != nil {
		return err
	}
	a.engineDataMu.RLock()
	defer a.engineDataMu.RUnlock()
	store, err := a.engineProfileStore()
	if err != nil {
		return err
	}
	if err := store.ClearSelection(); err != nil {
		return err
	}
	a.emit("engine-profiles:changed", struct{}{})
	return nil
}

// GetSelectedEngineProfileID is the engine profile that replaces the
// subscription as the connection, or "" when the subscription is used.
func (a *App) GetSelectedEngineProfileID() string {
	if ref := a.selectedEngineRoute(); ref != nil {
		return ref.ProfileID
	}
	return ""
}

// SelectEngineProfile makes an engine profile the connection (Android
// EngineProfilesUi.select). Saving a profile never selects it.
func (a *App) SelectEngineProfile(id string) error {
	if err := a.ensureRouteChangeAllowed(); err != nil {
		return err
	}
	err := func() error {
		a.engineDataMu.RLock()
		defer a.engineDataMu.RUnlock()
		store, err := a.engineProfileStore()
		if err != nil {
			return err
		}
		profile, err := store.ForEdit(id)
		if err != nil {
			return err
		}
		if reason := a.engineUnavailable(profile.Kind); reason != "" || !profile.Kind.SOCKS() {
			return fmt.Errorf("this engine is not available on this device")
		}
		return store.Select(engineprofiles.RouteRef{Kind: "engine", ProfileID: id})
	}()
	if err == nil {
		a.emit("engine-profiles:changed", struct {
			ID string `json:"id"`
		}{ID: id})
	}
	return err
}

// UseSubscriptionConnection drops the engine selection.
func (a *App) UseSubscriptionConnection() error { return a.clearEngineSelection() }

// GetPsiphonRegions is the country picker (Android PsiphonRegions.options).
func (a *App) GetPsiphonRegions(selected string) []string {
	return psiphon.Options(a.engineDataDir(engineprofiles.Psiphon), selected)
}

// engineProfileInUse guards edits to the profile carrying the connection
// (Android engine_stop_before_edit).
func (a *App) engineProfileInUse(id string) bool {
	snapshot := a.connectionManager().Snapshot()
	return snapshot.Route != nil && snapshot.Route.ProfileID == id && snapshot.Phase != sessionmanager.Disconnected
}

type engineBackend struct{ app *App }

func (b *engineBackend) Preflight(ctx context.Context, p sessionmanager.Plan) error {
	_, _, err := session.PrepareConfig(*p.Mihomo)
	return err
}

// Prepare resolves the Mihomo side of an engine route with the settings
// Android's EngineSettingsPolicy lets an engine use: destination rules, DNS,
// app split and proxy access. Chain, location, fronting, TLS integrity, noise,
// fragments and automatic ECH belong to subscription nodes and do not apply.
func (b *engineBackend) Prepare(ctx context.Context, p sessionmanager.Plan) (sessionmanager.Plan, error) {
	// Recorded like mihomoBackend.Prepare, so the refusal can be shown.
	prepared, err := b.prepare(ctx, p)
	reason := ""
	if err != nil {
		reason = model.PublicText(err.Error())
	}
	b.app.mu.Lock()
	b.app.preflightReason = reason
	b.app.mu.Unlock()
	return prepared, err
}

func (b *engineBackend) prepare(ctx context.Context, p sessionmanager.Plan) (sessionmanager.Plan, error) {
	a := b.app
	if reason := a.engineUnavailable(p.Profile.Kind); reason != "" {
		return p, fmt.Errorf("this engine is not available on this device (%s)", reason)
	}
	engine, _ := engines.Lookup(p.Profile.Kind)
	a.mu.Lock()
	settings := settingsForThisMachine(model.NormalizeWhiteVPNSettings(model.CloneWhiteVPNSettings(a.state.WhiteVPN)))
	a.mu.Unlock()
	if settings.DNSPrivacy.CredentialRequired && settings.DNSPrivacy.Mode != model.DNSPrivacyAutomatic {
		return p, model.ErrCredentialsRequired
	}
	// engineprofiles.Policy keeps LAN sharing off for engines.
	settings.AllowLAN = false
	if a.connectionManager().Snapshot().Phase != sessionmanager.Connected {
		a.setMihomoRuntimeType()
		a.handleRuntimeState(model.RuntimeConnecting, "Starting the connection engine")
	}
	core, err := engineMihomoCore()
	if err != nil {
		return p, err
	}
	port, err := chooseProxyPort(settings)
	if err != nil {
		old := a.mihomo.current()
		if old == nil || old.MixedPort() != settings.ListenPort {
			return p, err
		}
		port = old.MixedPort()
	}
	// Preflight renders against a placeholder port; Start swaps in the real one.
	placeholder, _ := engines.RuntimeYAML(1)
	opts := session.Options{CorePath: core, HomeDir: filepath.Join(a.configDir, "mihomo"), MixedPort: port,
		Subscription: placeholder, SplitTunnel: splitTunnelFor(settings), Direct: directRouteFor(settings),
		DNSPrivacy: dnsPrivacyMode(settings.DNSPrivacy.Mode), DoHURL: settings.DNSPrivacy.DoHURL, DoTEndpoint: settings.DNSPrivacy.DoTEndpoint,
		Tun: tunOptionsFor(settings), RejectUDP: true, Bypass: engine.BypassProcesses()}
	p.Mode = "proxy"
	if settings.TunEnabled {
		p.Mode = "tun"
	} else if !settings.SetSystemProxy {
		p.Mode = "proxy-only"
	}
	p.Mihomo = &opts
	return p, b.Preflight(ctx, p)
}

// Start is Android's engine flow: start the engine, then Mihomo with
// EngineRuntimeYaml pointed at the engine's SOCKS port.
func (b *engineBackend) Start(startup, lifetime context.Context, p sessionmanager.ActivePlan) (sessionmanager.Session, error) {
	a := b.app
	engine, ok := engines.Lookup(p.Profile.Kind)
	if !ok {
		return nil, sessionmanager.ErrUnavailable
	}
	log := func(line string) {
		a.connectionEvents.Lock()
		defer a.connectionEvents.Unlock()
		if a.connectionManager().Matches(p.SessionID, p.Generation) {
			a.appendRuntimeLog(line)
		}
	}
	proc, err := engine.Start(startup, engines.StartOptions{Profile: p.Profile, DataDir: a.engineDataDir(p.Profile.Kind), Binary: shippedBinary, Log: log})
	if err != nil {
		if proc != nil {
			return &engineSession{proc: proc}, err
		}
		return nil, err
	}
	yaml, err := engines.RuntimeYAML(proc.SOCKSPort())
	if err != nil {
		return &engineSession{proc: proc}, err
	}
	opts := p.Mihomo.Clone()
	opts.Subscription = yaml
	p.Mihomo = &opts
	owned, err := engineStartMihomo(a, startup, lifetime, p)
	s := &engineSession{mihomo: owned, proc: proc}
	// The engine dying under a running Mihomo is a failed session, as when
	// Mihomo itself exits.
	owned.launch(func(ctx context.Context) {
		select {
		case <-ctx.Done():
			return
		case <-proc.Done():
		}
		a.connectionEvents.Lock()
		defer a.connectionEvents.Unlock()
		if a.connectionManager().ReportFailure(p.SessionID, p.Generation) {
			a.syncManagedRuntimeLocked()
		}
	})
	return s, err
}

type engineSession struct {
	mihomo *managedMihomoSession
	proc   engines.Process
}

func (s *engineSession) WaitReady(ctx context.Context) error {
	if s.mihomo == nil {
		return fmt.Errorf("engine session has no Mihomo")
	}
	return s.mihomo.WaitReady(ctx)
}

// Stop releases Mihomo first (adapter, proxy settings), then the engine, and
// succeeds only when both are confirmed gone.
func (s *engineSession) Stop(ctx context.Context) error {
	if s.mihomo != nil {
		if err := s.mihomo.Stop(ctx); err != nil {
			return err
		}
	}
	if err := s.proc.Close(); err != nil {
		return err
	}
	select {
	case <-s.proc.Done():
		return nil
	default:
		return fmt.Errorf("the connection engine is still running")
	}
}

var engineTestMu sync.Mutex

// TestEngineProfile is Android's EngineProfileTester: through the running
// connection when it is this profile, otherwise in an isolated engine that is
// stopped again before returning. It reports the delay of one HTTPS request.
func (a *App) TestEngineProfile(id string) (string, error) {
	if !engineTestMu.TryLock() {
		return "", fmt.Errorf("another engine test is running")
	}
	defer engineTestMu.Unlock()
	profile, err := a.GetEngineProfileForEdit(id)
	if err != nil {
		return "", err
	}
	snapshot := a.connectionManager().Snapshot()
	if snapshot.Phase == sessionmanager.Connected && snapshot.Route != nil && snapshot.Route.ProfileID == id {
		return probeThrough(&url.URL{Scheme: "http", Host: a.GetLocalProxyEndpoint()})
	}
	if a.hasManagedOwner() || a.mihomo.current() != nil {
		return "", fmt.Errorf("stop the active connection before testing another engine")
	}
	if reason := a.engineUnavailable(profile.Kind); reason != "" {
		return "", fmt.Errorf("this engine is not available on this device")
	}
	engine, _ := engines.Lookup(profile.Kind)
	proc, err := engine.Start(context.Background(), engines.StartOptions{Profile: profile, DataDir: a.engineDataDir(profile.Kind), Binary: shippedBinary})
	if err != nil {
		if proc != nil {
			_ = proc.Close()
		}
		return "", fmt.Errorf("the engine did not connect")
	}
	result, probeErr := probeThrough(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", proc.SOCKSPort())})
	if err := proc.Close(); err != nil {
		return "", fmt.Errorf("engine test resources have not been released")
	}
	return result, probeErr
}

func probeThrough(proxy *url.URL) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := client.Get(mihomoconf.DelayTestURL)
	if err != nil {
		return "", fmt.Errorf("the test request failed")
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("the test request failed")
	}
	return fmt.Sprintf("%d ms", time.Since(start).Milliseconds()), nil
}

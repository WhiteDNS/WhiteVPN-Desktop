package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"whitevpn-desktop/internal/appdata"
	"whitevpn-desktop/internal/firewall"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

type firewallChecker func(context.Context) model.FirewallStatus

const runtimeLogLimit = 2000

var ensureAppDataWritable = appdata.EnsureAppDataWritable

var (
	runtimeLogURLPattern        = regexp.MustCompile(`\b(?:https?|wss?)://[^\s]+`)
	runtimeLogIPv4Endpoint      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	runtimeLogIPv6Endpoint      = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\]:\d{1,5}`)
	runtimeLogDomainEndpoint    = regexp.MustCompile(`\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}:\d{1,5}\b`)
	runtimeLogConfigField       = regexp.MustCompile(`\b(?:remote|dial|address|host_header|tls_server_name|server_name|serverName|sni|effective_sni|host|path|service|request_path)=("[^"]*"|\S+)`)
	runtimeLogConnectionArrow   = regexp.MustCompile(`->\s*\[redacted-endpoint\]`)
	runtimeLogDialDestination   = regexp.MustCompile(`\bto\s+\[redacted-endpoint\]`)
	runtimeLogListenDestination = regexp.MustCompile(`\blisten=\[redacted-endpoint\]`)
)

type App struct {
	ctx       context.Context
	store     *profiles.Store
	configDir string

	mu                         sync.Mutex
	state                      model.AppState
	v2rayTestMu                sync.Mutex
	v2rayTestCancel            context.CancelFunc
	v2rayTestRunID             int64
	validatorMu                sync.Mutex
	validatorState             model.ValidatorState
	validatorCancel            context.CancelFunc
	validatorRunID             int64
	validatorLastEmit          time.Time
	validatorLastMetadataWrite time.Time
	validatorPendingResults    []model.ValidatorResult
	validatorResultWriter      *validatorCSVWriter
	validatorResultsDir        string
	validatorDone              chan struct{}

	legacyImport profiles.LegacyImport

	mihomo  mihomoState
	tray    trayState
	measure measureState
	// Cached so opening a page does not spend one of GitHub's sixty
	// unauthenticated requests an hour.
	updates updateCheckCache

	connectMu     sync.Mutex
	connectCancel context.CancelFunc

	// The catalogues, one per subscription: the Servers page browses any of
	// them while the connect path uses the selected one, and a shared slot
	// would let the first quietly answer for the second. Measurements live here
	// too, which is why switching between subscriptions does not lose them.
	nodesMu sync.Mutex
	nodes   map[string][]model.WhiteVPNNode
	nodesAt map[string]time.Time

	firewallChecker       firewallChecker
	lastFirewallStatusKey string
	emitHook              func(name string, payload any)

	proxyCountryMu    sync.Mutex
	proxyCountryCache map[string]proxyCountryCacheEntry
}

func NewApp() (*App, error) {
	_ = raiseProcessFileDescriptorLimit()
	configDir, err := appConfigDir()
	if err != nil {
		return nil, err
	}
	if err := ensureAppDataWritable(context.Background(), configDir); err != nil {
		return nil, err
	}
	statePath := filepath.Join(configDir, "state.json")
	// Look for a WhiteDNS Desktop install to inherit from, but only before this
	// app has a state file of its own - after that the user has made their own
	// choices here and we must not second-guess them.
	firstRun := false
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		firstRun = true
	}
	store := profiles.NewStore(statePath)
	app := &App{
		store:               store,
		configDir:           configDir,
		validatorState:      model.ValidatorState{Status: model.ValidatorIdle},
		validatorResultsDir: filepath.Join(configDir, validatorResultsDirName),
		firewallChecker:     firewall.Detect,
		proxyCountryCache:   map[string]proxyCountryCacheEntry{},
	}
	state, err := store.Load()
	if err != nil {
		return nil, err
	}
	app.state = forgetBuiltInCatalogueProfiles(forgetBuiltInSubscriptionURL(state))
	// The catalogue has to be in the list from the first launch, not from the
	// first refresh.
	//
	// It was only ever added by a catalogue refresh or by recording an error
	// against one, so a fresh install listed no subscriptions at all: the
	// Servers page's source picker was empty and the Subscriptions page said "0
	// sources", while the catalogue itself worked — the connect path defaults to
	// its id whatever the list says. Anyone who had refreshed once never saw it
	// again, which is why it survived this long: every developer machine had
	// been through that by the time anyone looked.
	app.ensureWhiteDNSVPNSubscriptionLocked()
	if firstRun {
		app.legacyImport = profiles.ReadLegacyImport(legacyWhiteDNSStatePath())
	}
	return app, nil
}

// legacyWhiteDNSStatePath is where WhiteDNS Desktop keeps its state. It is only
// ever read from.
func legacyWhiteDNSStatePath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "WhiteDNS Desktop", "state.json")
}

// GetLegacyImportOffer reports whether there are WhiteDNS Desktop profiles
// worth importing. It is empty on every launch but the first.
func (a *App) GetLegacyImportOffer() profiles.LegacyImport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.legacyImport
}

// ImportLegacyProfiles copies the offered profiles in. The offer is cleared
// either way, so declining is remembered for the rest of the session and
// accepting cannot run twice.
func (a *App) ImportLegacyProfiles() (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	offer := a.legacyImport
	a.legacyImport = profiles.LegacyImport{}
	if !offer.Available {
		return a.state, nil
	}
	a.state = forgetBuiltInCatalogueProfiles(forgetBuiltInSubscriptionURL(offer.Apply(a.state)))
	return a.saveLocked()
}

// DismissLegacyImportOffer declines the offer without importing anything.
func (a *App) DismissLegacyImportOffer() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.legacyImport = profiles.LegacyImport{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// A backup still on disk means the last run ended without putting the
	// machine's proxy back — a crash, a kill, a power cut. Nothing else will
	// ever do it, so it is done here before anything else can connect.
	a.restoreSystemProxy()
	a.startTray()
	a.emit("runtime:state", a.currentRuntime())
	a.emit("validator:state", a.GetValidatorState())
}

func (a *App) shutdown(ctx context.Context) {
	systray.Quit()
	a.stopMihomo()
	_ = a.CancelV2RayProfileTests()
	_, _ = a.CancelValidatorScan()
	a.waitValidatorStopped(5 * time.Second)
}

func (a *App) GetAppState() model.AppState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

func (a *App) CheckFirewallStatus() model.FirewallStatus {
	return a.checkFirewallStatus(context.Background())
}

func (a *App) GetSystemLANIP() string {
	return detectShareNetworkIPv4()
}

func validatorEndpointDisplay(host string, port int) string {
	if port <= 0 {
		return host
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (a *App) StopConnection() (model.AppState, error) {
	// A connect that is still running is stopped by cancelling it, not by
	// waiting for it to finish and then tearing down what it built. It unwinds
	// on its own and reports itself disconnected.
	a.cancelConnect()
	a.beginStopping()

	if !a.stopMihomo() {
		// Nothing was running; there is still a status to settle, because a
		// cancelled connect leaves one behind.
		a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	}
	return a.GetAppState(), nil
}

// beginStopping marks a running runtime as on its way down, and reports whether
// there was anything to stop: stopping what is already stopped must not flash a
// state the user was never in.
func (a *App) beginStopping() bool {
	a.mu.Lock()
	switch a.state.Runtime.Status {
	case model.RuntimeConnecting, model.RuntimeConnected:
	default:
		a.mu.Unlock()
		return false
	}
	a.state.Runtime.Status = model.RuntimeStopping
	a.state.Runtime.Message = "Disconnecting"
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	a.emit("runtime:state", runtimeState)
	return true
}

func (a *App) ClearRuntimeLogs() model.AppState {
	return a.ClearRuntimeLogsForType("")
}

func (a *App) ClearRuntimeLogsForType(runtimeType string) model.AppState {
	a.mu.Lock()
	switch normalizeRuntimeType(runtimeType) {
	case model.RuntimeTypeMasterDNS:
		a.state.Runtime.MasterDNSLogs = []string{}
	case model.RuntimeTypeV2Ray:
		a.state.Runtime.V2RayLogs = []string{}
	default:
		a.state.Runtime.Logs = []string{}
		a.state.Runtime.MasterDNSLogs = []string{}
		a.state.Runtime.V2RayLogs = []string{}
	}
	runtimeState := a.state.Runtime
	next := a.state
	a.mu.Unlock()
	a.emit("runtime:state", runtimeState)
	return next
}

func (a *App) ExportBackup() (string, error) {
	a.mu.Lock()
	state := a.state
	a.mu.Unlock()
	return a.store.ExportBackup(state)
}

func (a *App) ImportBackup(rawText string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.Status != model.RuntimeFailed {
		return a.state, fmt.Errorf("backup can only be restored while disconnected")
	}

	next, err := a.store.ImportBackup(rawText)
	if err != nil {
		return a.state, err
	}
	a.state = forgetBuiltInCatalogueProfiles(forgetBuiltInSubscriptionURL(next))
	return a.state, nil
}

func (a *App) Quit() {
	a.shutdown(context.Background())
	if a.ctx != nil {
		wailsruntime.Quit(a.ctx)
	}
}

func reorderProfiles[T any](profiles []T, ids []string, profileID func(T) string, label string) ([]T, error) {
	if len(ids) != len(profiles) {
		return nil, fmt.Errorf("%s reorder must include exactly %d IDs", label, len(profiles))
	}

	byID := make(map[string]T, len(profiles))
	for _, profile := range profiles {
		id := strings.TrimSpace(profileID(profile))
		if _, exists := byID[id]; exists {
			return nil, fmt.Errorf("%s list contains duplicate ID %q", label, id)
		}
		byID[id] = profile
	}

	seen := make(map[string]struct{}, len(ids))
	reordered := make([]T, 0, len(profiles))
	for _, rawID := range ids {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, fmt.Errorf("%s reorder contains an empty ID", label)
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("%s reorder contains duplicate ID %q", label, id)
		}
		profile, exists := byID[id]
		if !exists {
			return nil, fmt.Errorf("%s reorder contains unknown ID %q", label, id)
		}
		seen[id] = struct{}{}
		reordered = append(reordered, profile)
	}

	return reordered, nil
}

func (a *App) connectionSelectionLockedLocked() bool {
	switch a.state.Runtime.Status {
	case "", model.RuntimeDisconnected, model.RuntimeFailed:
		return false
	default:
		return true
	}
}

func (a *App) saveLocked() (model.AppState, error) {
	a.state = profiles.NormalizeStatePreservingRuntime(a.state)
	next, err := a.store.SaveState(a.state)
	if err != nil {
		return a.state, err
	}
	a.state = next
	return a.state, nil
}

func (a *App) handleLog(line string) {
	a.mu.Lock()
	runtimeType := a.activeRuntimeTypeLocked()
	line = sanitizeRuntimeLogLine(runtimeType, line)
	if line == "" {
		a.mu.Unlock()
		return
	}
	a.appendRuntimeLogLocked(runtimeType, line)
	a.mu.Unlock()
	a.emit("runtime:log", model.RuntimeLogEntry{RuntimeType: runtimeType, Line: line})
}

func (a *App) handleRuntimeState(status, message string) {
	message = strings.TrimSpace(message)
	a.mu.Lock()
	a.state.Runtime.Status = status
	a.state.Runtime.Message = message
	if status == model.RuntimeConnected {
		a.state.Runtime.Progress.Phase = "ready"
		a.state.Runtime.Progress.Percent = 100
		if a.state.Runtime.Progress.Total > 0 {
			a.state.Runtime.Progress.Completed = a.state.Runtime.Progress.Total
		}
	}
	if status == model.RuntimeFailed {
		a.state.Runtime.Progress = model.ConnectionProgress{Phase: "failed"}
	}
	if status == model.RuntimeDisconnected {
		a.state.Runtime.Progress = model.ConnectionProgress{}
	}
	clearProxyCountryCache := status == model.RuntimeDisconnected || status == model.RuntimeFailed
	if clearProxyCountryCache {
		if status == model.RuntimeDisconnected {
			a.state.Runtime.RuntimeType = ""
		}
		a.state.Runtime.ActiveConnectionID = ""
		a.state.Runtime.ListenIP = ""
		a.state.Runtime.ListenPort = 0
		a.state.Runtime.ProxyProtocol = ""
		a.state.Runtime.LocalProxyIP = ""
		a.state.Runtime.PublicProxyIP = ""
		a.state.Runtime.ExitIP = ""
		a.state.Runtime.NodeName = ""
		a.state.Runtime.NodeCountryCode = ""
		a.state.Runtime.ExitCountryCode = ""
		a.state.Runtime.ExitChecked = false
		a.state.Runtime.ResolverMTUScanPaused = false
		a.state.Runtime.AutoProfilePresetID = ""
		a.state.Runtime.AutoProfileName = ""
		a.state.Runtime.ResolverState = model.ResolverRuntimeState{}
		a.state.Runtime.Stats = model.TrafficStats{}
		a.state.Runtime.TrafficMonitorMessage = ""
	}
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	if clearProxyCountryCache {
		a.clearProxyCountryCache()
	}
	a.emit("runtime:state", runtimeState)
}

func (a *App) handleProgress(progress model.ConnectionProgress) {
	a.mu.Lock()
	if !a.acceptsLiveRuntimeUpdateLocked() {
		a.mu.Unlock()
		return
	}
	a.state.Runtime.Progress = progress
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	a.emit("runtime:progress", progress)
	a.emit("runtime:state", runtimeState)
}

func (a *App) handleStats(stats model.TrafficStats) {
	a.mu.Lock()
	if !a.acceptsLiveRuntimeUpdateLocked() {
		a.mu.Unlock()
		return
	}
	a.state.Runtime.Stats = stats
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	a.emit("runtime:stats", stats)
	a.emit("runtime:state", runtimeState)
}

func (a *App) handleTrafficMonitorStatus(message string) {
	message = strings.TrimSpace(message)
	a.mu.Lock()
	if !a.acceptsLiveRuntimeUpdateLocked() {
		a.mu.Unlock()
		return
	}
	if a.state.Runtime.TrafficMonitorMessage == message {
		a.mu.Unlock()
		return
	}
	a.state.Runtime.TrafficMonitorMessage = message
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	a.emit("runtime:state", runtimeState)
}

func (a *App) acceptsLiveRuntimeUpdateLocked() bool {
	return a.state.Runtime.Status == model.RuntimeConnecting || a.state.Runtime.Status == model.RuntimeConnected
}

func (a *App) notifyFirewallIfEnabled(ctx context.Context) {
	status := a.checkFirewallStatus(ctx)
	key := firewallStatusKey(status)

	a.mu.Lock()
	shouldEmit := status.Supported && status.Enabled && key != a.lastFirewallStatusKey
	a.lastFirewallStatusKey = key
	a.mu.Unlock()

	if shouldEmit {
		a.emit("firewall:enabled", status)
	}
}

func (a *App) checkFirewallStatus(ctx context.Context) model.FirewallStatus {
	checker := a.firewallChecker
	if checker == nil {
		checker = firewall.Detect
	}
	return checker(ctx)
}

func firewallStatusKey(status model.FirewallStatus) string {
	return fmt.Sprintf("%t|%t|%s|%s", status.Supported, status.Enabled, status.Name, status.Message)
}

func (a *App) handleRuntimeError(message string) {
	message = strings.TrimSpace(message)
	if strings.TrimSpace(message) != "" {
		a.mu.Lock()
		runtimeType := a.activeRuntimeTypeLocked()
		message = redactRuntimeEndpointConfig(runtimeType, message)
		if a.state.Runtime.Status != model.RuntimeDisconnected {
			a.state.Runtime.Message = message
			runtimeState := a.state.Runtime
			a.mu.Unlock()
			a.emit("runtime:state", runtimeState)
		} else {
			a.mu.Unlock()
		}
	}
	a.emit("runtime:error", message)
	a.handleLog(message)
}

func (a *App) handleLogForActiveRuntime(runtimeType string, activeConnectionID string, line string) {
	runtimeType = normalizeRuntimeType(runtimeType)
	line = sanitizeRuntimeLogLine(runtimeType, line)
	if line == "" {
		return
	}
	a.mu.Lock()
	if strings.TrimSpace(activeConnectionID) != "" && strings.TrimSpace(a.state.Runtime.ActiveConnectionID) != strings.TrimSpace(activeConnectionID) {
		a.mu.Unlock()
		return
	}
	a.appendRuntimeLogLocked(runtimeType, line)
	a.mu.Unlock()
	a.emit("runtime:log", model.RuntimeLogEntry{RuntimeType: runtimeType, Line: line})
}

func sanitizeRuntimeLogLines(runtimeType string, lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if cleaned := sanitizeRuntimeLogLine(runtimeType, line); cleaned != "" {
			out = append(out, cleaned)
		}
	}
	return out
}

func sanitizeRuntimeLogLine(runtimeType string, line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	return redactRuntimeEndpointConfig(runtimeType, line)
}

func redactRuntimeEndpointConfig(runtimeType string, line string) string {
	if normalizeRuntimeType(runtimeType) != model.RuntimeTypeV2Ray {
		return line
	}
	line = runtimeLogURLPattern.ReplaceAllString(line, "[redacted-url]")
	line = runtimeLogConfigField.ReplaceAllStringFunc(line, func(match string) string {
		if idx := strings.IndexByte(match, '='); idx >= 0 {
			return match[:idx+1] + "[redacted]"
		}
		return "[redacted]"
	})
	line = runtimeLogIPv6Endpoint.ReplaceAllString(line, "[redacted-endpoint]")
	line = runtimeLogIPv4Endpoint.ReplaceAllString(line, "[redacted-endpoint]")
	line = runtimeLogDomainEndpoint.ReplaceAllString(line, "[redacted-endpoint]")
	line = runtimeLogConnectionArrow.ReplaceAllString(line, "-> [redacted-endpoint]")
	line = runtimeLogDialDestination.ReplaceAllString(line, "to [redacted-endpoint]")
	line = runtimeLogListenDestination.ReplaceAllString(line, "listen=[redacted-endpoint]")
	return line
}

func (a *App) appendRuntimeLogLocked(runtimeType string, line string) {
	a.state.Runtime.Logs = appendRuntimeLog([]string{line}, a.state.Runtime.Logs...)
	switch normalizeRuntimeType(runtimeType) {
	case model.RuntimeTypeMasterDNS:
		a.state.Runtime.MasterDNSLogs = appendRuntimeLog([]string{line}, a.state.Runtime.MasterDNSLogs...)
	case model.RuntimeTypeV2Ray:
		a.state.Runtime.V2RayLogs = appendRuntimeLog([]string{line}, a.state.Runtime.V2RayLogs...)
	}
}

func appendRuntimeLog(prefix []string, logs ...string) []string {
	out := append(append([]string{}, prefix...), logs...)
	if len(out) > runtimeLogLimit {
		return out[:runtimeLogLimit]
	}
	return out
}

func (a *App) activeRuntimeTypeLocked() string {
	if runtimeType := normalizeRuntimeType(a.state.Runtime.RuntimeType); runtimeType != "" {
		return runtimeType
	}
	activeConnectionID := strings.TrimSpace(a.state.Runtime.ActiveConnectionID)
	if activeConnectionID == "" {
		return ""
	}
	if activeRuntimeIsV2Ray(a.state, activeConnectionID) {
		return model.RuntimeTypeV2Ray
	}
	for _, profile := range a.state.ConnectionProfiles {
		if profile.ID == activeConnectionID {
			return model.RuntimeTypeMasterDNS
		}
	}
	return ""
}

func normalizeRuntimeType(runtimeType string) string {
	switch strings.ToLower(strings.TrimSpace(runtimeType)) {
	case model.RuntimeTypeMasterDNS:
		return model.RuntimeTypeMasterDNS
	case model.RuntimeTypeV2Ray:
		return model.RuntimeTypeV2Ray
	default:
		return ""
	}
}

func (a *App) currentRuntime() model.RuntimeStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.Runtime
}

func (a *App) emit(name string, payload any) {
	if a.emitHook != nil {
		a.emitHook(name, payload)
	}
	if name == "runtime:state" {
		// The tray shows the same status the page does, so it learns about it
		// the same way rather than polling for it.
		a.notifyTray()
	}
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, name, payload)
}

// appDataDirName is the one folder this app owns. Named rather than repeated so
// the reset can check it is deleting that and nothing else.
const appDataDirName = "WhiteVPN Desktop"

func appConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, appDataDirName), nil
}

func findCoresDir() string {
	for _, candidate := range appRelativeDirs("cores") {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

func appRelativeDirs(name string) []string {
	candidates := make([]string, 0)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, name),
			filepath.Join(cwd, "..", name),
			filepath.Join(cwd, "..", "..", name),
			filepath.Join(cwd, "desktop", name),
		)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, name),
			filepath.Join(dir, "..", name),
			filepath.Join(dir, "..", "..", name),
			filepath.Join(dir, "..", "..", "..", name),
			filepath.Join(dir, "Resources", name),
			filepath.Join(dir, "..", "Resources", name),
			filepath.Join(dir, "..", "..", "Resources", name),
		)
	}
	return candidates
}

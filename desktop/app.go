package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"whitevpn-desktop/internal/appdata"
	"whitevpn-desktop/internal/firewall"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/resolver"
	runtimemgr "whitevpn-desktop/internal/runtime"
	"whitevpn-desktop/internal/storm"
)

type firewallChecker func(context.Context) model.FirewallStatus
type runtimeManagerFactory func(runtimeDir string, callbacks runtimemgr.Callbacks) parallelRuntimeManager

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
	manager   *runtimemgr.Manager
	configDir string

	mu                         sync.Mutex
	state                      model.AppState
	parallelMu                 sync.Mutex
	parallelState              model.ParallelTestState
	parallelCancel             context.CancelFunc
	parallelRunID              int64
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
	scannerMu                  sync.Mutex
	scannerState               model.ScannerState
	scannerInputPath           string
	scannerControlFile         string
	scannerRuntimeDir          string
	scannerSnapshotPath        string
	scannerResultsPath         string
	scannerCancel              context.CancelFunc
	scannerRunID               int64
	scannerInputStarted        bool
	scannerAutoApplyStarted    bool

	firewallChecker       firewallChecker
	runtimeManagerFactory runtimeManagerFactory
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
	runtimeDir := filepath.Join(configDir, "runtime")
	scannerSnapshotPath, scannerResultsPath, err := scannerPersistencePaths(configDir)
	if err != nil {
		return nil, err
	}
	store := profiles.NewStore(filepath.Join(configDir, "state.json"))
	scannerState := model.ScannerState{Status: model.ScannerIdle, Mode: dnsScannerModeManual, ScanParallel: defaultDNSScannerParallel}
	scannerInputPath := ""
	if recoveredState, recoveredInputPath, ok := loadPersistedScannerSnapshot(scannerSnapshotPath, scannerResultsPath); ok {
		scannerState = recoveredState
		scannerInputPath = recoveredInputPath
	}
	app := &App{
		store:               store,
		configDir:           configDir,
		parallelState:       model.DefaultParallelTestState(),
		validatorState:      model.ValidatorState{Status: model.ValidatorIdle},
		validatorResultsDir: filepath.Join(configDir, validatorResultsDirName),
		scannerState:        scannerState,
		scannerInputPath:    scannerInputPath,
		scannerSnapshotPath: scannerSnapshotPath,
		scannerResultsPath:  scannerResultsPath,
		firewallChecker:     firewall.Detect,
		proxyCountryCache:   map[string]proxyCountryCacheEntry{},
	}
	app.manager = runtimemgr.NewManager(
		runtimeManagerOptions(runtimeDir),
		runtimemgr.Callbacks{
			OnLog:           app.handleLog,
			OnState:         app.handleRuntimeState,
			OnProgress:      app.handleProgress,
			OnResolverState: app.handleResolverState,
			OnStats:         app.handleStats,
			OnTrafficStatus: app.handleTrafficMonitorStatus,
			OnError:         app.handleRuntimeError,
		},
	)
	state, err := store.Load()
	if err != nil {
		return nil, err
	}
	app.state = state
	return app, nil
}

func runtimeManagerOptions(runtimeDir string) runtimemgr.Options {
	return runtimemgr.Options{
		RuntimeDir:        runtimeDir,
		MasterDNSSource:   findMasterDNSSourceDir(),
		ClientsDir:        findClientsDir(),
		XrayCoresDir:      findXrayCoresDir(),
		EmbeddedClientsFS: clientAssets,
		EmbeddedCoresFS:   coreAssets,
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.emit("runtime:state", a.currentRuntime())
	a.emit("validator:state", a.GetValidatorState())
	a.emit("scanner:state", a.GetScannerState())
	a.emit("parallel-test:state", a.GetParallelTestState())
}

func (a *App) shutdown(ctx context.Context) {
	_ = a.manager.Stop()
	_ = a.CancelV2RayProfileTests()
	_, _ = a.CancelParallelTest()
	_, _ = a.CancelValidatorScan()
	a.waitValidatorStopped(5 * time.Second)
	_, _ = a.CancelScannerScan()
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

func (a *App) SaveConnectionProfile(profile model.ConnectionProfile) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.ID == "" {
		profile.ID = fmt.Sprintf("profile-%d", time.Now().UnixMilli())
	}
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = "Connection"
	}
	profile.ImportType = model.NormalizeImportType(profile.ImportType)
	profile.Domain = strings.TrimSpace(strings.TrimSuffix(profile.Domain, "."))
	profile.EncryptionKey = strings.TrimSpace(profile.EncryptionKey)
	if profile.EncryptionMethod < 0 || profile.EncryptionMethod > 5 {
		profile.EncryptionMethod = 1
	}

	found := false
	for idx := range a.state.ConnectionProfiles {
		if a.state.ConnectionProfiles[idx].ID == profile.ID {
			a.state.ConnectionProfiles[idx] = profile
			found = true
			break
		}
	}
	if !found {
		a.state.ConnectionProfiles = append(a.state.ConnectionProfiles, profile)
	}
	if !a.connectionSelectionLockedLocked() {
		a.state.SelectedConnectionProfileID = profile.ID
		if profile.ResolverProfileID != "" {
			a.state.SelectedResolverProfileID = profile.ResolverProfileID
		}
	}
	return a.saveLocked()
}

func (a *App) ImportConnectionProfiles(rawText string, importType string) (model.ConnectionImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	imported, err := profiles.ParseConnectionProfileImports(rawText, a.state.SelectedResolverProfileID, importType)
	if err != nil {
		return model.ConnectionImportResult{State: a.state}, err
	}

	existingIDs := make(map[string]struct{}, len(a.state.ConnectionProfiles)+len(imported))
	for _, profile := range a.state.ConnectionProfiles {
		existingIDs[profile.ID] = struct{}{}
	}

	baseID := time.Now().UnixNano()
	for idx := range imported {
		imported[idx].ID = uniqueImportedConnectionID(existingIDs, baseID, idx)
		if imported[idx].ResolverProfileID == "" {
			imported[idx].ResolverProfileID = a.state.SelectedResolverProfileID
		}
		a.state.ConnectionProfiles = append(a.state.ConnectionProfiles, imported[idx])
	}
	if !a.connectionSelectionLockedLocked() {
		a.state.SelectedConnectionProfileID = imported[len(imported)-1].ID
	}

	next, err := a.saveLocked()
	return model.ConnectionImportResult{State: next, Imported: len(imported)}, err
}

func (a *App) CreateResolverProfileFromValidatorResults(request model.ValidatorResolverProfileRequest) (model.ResolverImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(request.Results) == 0 {
		return model.ResolverImportResult{State: a.state}, fmt.Errorf("no validator results selected")
	}

	resolverLines := make([]string, 0, len(request.Results))
	for _, result := range request.Results {
		entry := validatorResolverEntry(result)
		if entry != "" {
			resolverLines = append(resolverLines, entry)
		}
	}
	validation := resolver.ValidateText(strings.Join(resolverLines, "\n"))
	imported := len(validation.NormalizedResolvers)
	skipped := len(request.Results) - imported
	if imported == 0 {
		return model.ResolverImportResult{State: a.state, Imported: imported, Skipped: skipped}, fmt.Errorf("no valid validator results selected")
	}

	profile := model.ResolverProfile{
		ID:             a.uniqueResolverProfileIDLocked("resolver-validator"),
		Name:           "Validated Resolvers",
		ResolverText:   validation.NormalizedText,
		ResolverSource: "inline",
	}
	a.state.ResolverProfiles = append(a.state.ResolverProfiles, profile)
	if !a.resolverSelectionLockedLocked() {
		a.state.SelectedResolverProfileID = profile.ID
		a.applyResolverToSelectedConnectionLocked(profile.ID)
	}
	next, err := a.saveLocked()
	return model.ResolverImportResult{State: next, Profile: profile, Imported: imported, Skipped: skipped}, err
}

func validatorResolverEntry(result model.ValidatorResolverProfileInput) string {
	host := strings.TrimSpace(strings.TrimSuffix(result.Host, "."))
	if host != "" {
		return validatorEndpointDisplay(host, result.Port)
	}
	return strings.TrimSpace(result.Endpoint)
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

func (a *App) DeleteConnectionProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id == model.DefaultConnectionProfileID {
		return a.state, fmt.Errorf("default connection profile cannot be deleted")
	}
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.ActiveConnectionID == id {
		return a.state, fmt.Errorf("active connection profile cannot be deleted")
	}
	a.state.ConnectionProfiles = slices.DeleteFunc(a.state.ConnectionProfiles, func(profile model.ConnectionProfile) bool {
		return profile.ID == id
	})
	return a.saveLocked()
}

func (a *App) DeleteConnectionProfiles(ids []string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	remove := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" || trimmed == model.DefaultConnectionProfileID {
			continue
		}
		remove[trimmed] = struct{}{}
	}
	if len(remove) == 0 {
		return a.state, nil
	}
	if a.state.Runtime.Status != model.RuntimeDisconnected {
		if _, ok := remove[a.state.Runtime.ActiveConnectionID]; ok {
			return a.state, fmt.Errorf("active connection profile cannot be deleted")
		}
	}
	a.state.ConnectionProfiles = slices.DeleteFunc(a.state.ConnectionProfiles, func(profile model.ConnectionProfile) bool {
		_, ok := remove[profile.ID]
		return ok
	})
	return a.saveLocked()
}

func uniqueImportedConnectionID(existingIDs map[string]struct{}, baseID int64, index int) string {
	for attempt := 0; ; attempt++ {
		id := fmt.Sprintf("profile-import-%d-%d-%d", baseID, index, attempt)
		if _, exists := existingIDs[id]; !exists {
			existingIDs[id] = struct{}{}
			return id
		}
	}
}

func (a *App) SelectConnectionProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !slices.ContainsFunc(a.state.ConnectionProfiles, func(profile model.ConnectionProfile) bool { return profile.ID == id }) {
		return a.state, fmt.Errorf("connection profile not found")
	}
	if a.connectionSelectionLockedLocked() {
		return a.state, fmt.Errorf("connection profile cannot be changed while connected")
	}
	a.state.SelectedConnectionProfileID = id
	for _, profile := range a.state.ConnectionProfiles {
		if profile.ID == id && profile.ResolverProfileID != "" {
			a.state.SelectedResolverProfileID = profile.ResolverProfileID
			break
		}
	}
	return a.saveLocked()
}

func (a *App) ReorderConnectionProfiles(ids []string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reordered, err := reorderProfiles(a.state.ConnectionProfiles, ids, func(profile model.ConnectionProfile) string {
		return profile.ID
	}, "connection profile")
	if err != nil {
		return a.state, err
	}
	a.state.ConnectionProfiles = reordered
	return a.saveLocked()
}

func (a *App) SaveResolverProfile(profile model.ResolverProfile) (model.AppState, error) {
	return a.saveResolverProfile(profile, true)
}

func (a *App) SaveResolverProfileSnapshot(profile model.ResolverProfile) (model.AppState, error) {
	return a.saveResolverProfile(profile, false)
}

func (a *App) saveResolverProfile(profile model.ResolverProfile, selectAfterSave bool) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.ID == "" {
		profile.ID = a.uniqueResolverProfileIDLocked("resolver")
	}
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = "Resolvers"
	}
	if strings.EqualFold(strings.TrimSpace(profile.ResolverSource), "file") {
		if strings.TrimSpace(profile.ResolverFile) == "" {
			return a.state, fmt.Errorf("resolver profile file is missing")
		}
		if info, err := os.Stat(profile.ResolverFile); err != nil || info.IsDir() {
			return a.state, fmt.Errorf("resolver profile file is unavailable")
		}
		profile.ResolverSource = "file"
		profile.ResolverText = ""
	} else if !profiles.ResolverTextShouldBeFileBacked(profile.ResolverText) {
		validation := resolver.ValidateText(profile.ResolverText)
		if profile.ID != model.DefaultResolverProfileID && !validation.IsValid {
			return a.state, fmt.Errorf("resolver profile must contain at least one valid resolver and no invalid entries")
		}
		profile.ResolverSource = "inline"
		profile.ResolverText = validation.NormalizedText
		profile.ResolverFile = ""
		profile.ResolverCount = 0
		profile.ResolverPreview = nil
		profile.ResolverInvalidCount = 0
	}

	found := false
	for idx := range a.state.ResolverProfiles {
		if a.state.ResolverProfiles[idx].ID == profile.ID {
			a.state.ResolverProfiles[idx] = profile
			found = true
			break
		}
	}
	if !found {
		a.state.ResolverProfiles = append(a.state.ResolverProfiles, profile)
	}
	if selectAfterSave && !a.resolverSelectionLockedLocked() {
		a.state.SelectedResolverProfileID = profile.ID
		a.applyResolverToSelectedConnectionLocked(profile.ID)
	}
	return a.saveLocked()
}

func (a *App) ImportResolverProfileFile() (model.ResolverImportResult, error) {
	if a.ctx == nil {
		return model.ResolverImportResult{State: a.GetAppState()}, fmt.Errorf("file picker is unavailable")
	}
	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Import resolver list",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Resolver lists (*.txt, *.csv, *.lst)", Pattern: "*.txt;*.csv;*.lst;*.resolvers"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return model.ResolverImportResult{State: a.GetAppState()}, err
	}
	if strings.TrimSpace(path) == "" {
		return model.ResolverImportResult{State: a.GetAppState()}, nil
	}
	return a.importResolverProfileFilePath(path)
}

func (a *App) importResolverProfileFilePath(path string) (model.ResolverImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	profile, err := a.store.ImportResolverFile(path)
	if err != nil {
		return model.ResolverImportResult{State: a.state}, err
	}
	a.state.ResolverProfiles = append(a.state.ResolverProfiles, profile)
	if !a.resolverSelectionLockedLocked() {
		a.state.SelectedResolverProfileID = profile.ID
		a.applyResolverToSelectedConnectionLocked(profile.ID)
	}
	next, err := a.saveLocked()
	return model.ResolverImportResult{
		State:    next,
		Profile:  profile,
		Imported: profile.ResolverCount,
		Skipped:  profile.ResolverInvalidCount,
	}, err
}

func (a *App) DeleteResolverProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id == model.DefaultResolverProfileID {
		return a.state, fmt.Errorf("default resolver profile cannot be deleted")
	}
	if a.resolverSelectionLockedLocked() && a.resolverProfileIsEffectiveLocked(id) {
		return a.state, fmt.Errorf("active resolver profile cannot be deleted while connected")
	}
	for _, profile := range a.state.ResolverProfiles {
		if profile.ID == id && strings.EqualFold(profile.ResolverSource, "file") && strings.TrimSpace(profile.ResolverFile) != "" {
			_ = os.Remove(profile.ResolverFile)
			break
		}
	}
	a.state.ResolverProfiles = slices.DeleteFunc(a.state.ResolverProfiles, func(profile model.ResolverProfile) bool {
		return profile.ID == id
	})
	for idx := range a.state.ConnectionProfiles {
		if a.state.ConnectionProfiles[idx].ResolverProfileID == id {
			a.state.ConnectionProfiles[idx].ResolverProfileID = ""
		}
	}
	return a.saveLocked()
}

func (a *App) SelectResolverProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !slices.ContainsFunc(a.state.ResolverProfiles, func(profile model.ResolverProfile) bool { return profile.ID == id }) {
		return a.state, fmt.Errorf("resolver profile not found")
	}
	if a.resolverSelectionLockedLocked() {
		return a.state, fmt.Errorf("resolver profile cannot be changed while connected")
	}
	a.state.SelectedResolverProfileID = id
	a.applyResolverToSelectedConnectionLocked(id)
	return a.saveLocked()
}

func (a *App) ReorderResolverProfiles(ids []string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reordered, err := reorderProfiles(a.state.ResolverProfiles, ids, func(profile model.ResolverProfile) string {
		return profile.ID
	}, "resolver profile")
	if err != nil {
		return a.state, err
	}
	a.state.ResolverProfiles = reordered
	return a.saveLocked()
}

func (a *App) SaveSettingsProfile(profile model.SettingsProfile) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(profile.ID) == "" {
		profile.ID = fmt.Sprintf("settings-%d", time.Now().UnixMilli())
	}
	profile = profiles.NormalizeSettingsProfile(profile)
	if profile.ID == model.DefaultSettingsProfileID {
		return a.state, fmt.Errorf("default settings profile cannot be edited; create a new profile")
	}
	found := false
	for idx := range a.state.SettingsProfiles {
		if a.state.SettingsProfiles[idx].ID == profile.ID {
			a.state.SettingsProfiles[idx] = profile
			found = true
			break
		}
	}
	if !found {
		a.state.SettingsProfiles = append(a.state.SettingsProfiles, profile)
	}
	a.state.SelectedSettingsProfileID = profile.ID
	return a.saveLocked()
}

func (a *App) ImportSettingsProfileToml(rawText, suggestedName string, importType string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	profile, err := storm.ParseSettingsProfileTOML(rawText, suggestedName, importType)
	if err != nil {
		return a.state, err
	}

	existingIDs := make(map[string]struct{}, len(a.state.SettingsProfiles)+1)
	for _, existing := range a.state.SettingsProfiles {
		existingIDs[existing.ID] = struct{}{}
	}
	profile.ID = uniqueImportedSettingsID(existingIDs, time.Now().UnixNano())
	a.state.SettingsProfiles = append(a.state.SettingsProfiles, profile)
	a.state.SelectedSettingsProfileID = profile.ID
	return a.saveLocked()
}

func (a *App) DeleteSettingsProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id == model.DefaultSettingsProfileID {
		return a.state, fmt.Errorf("default setting profile cannot be deleted")
	}
	a.state.SettingsProfiles = slices.DeleteFunc(a.state.SettingsProfiles, func(profile model.SettingsProfile) bool {
		return profile.ID == id
	})
	return a.saveLocked()
}

func uniqueImportedSettingsID(existingIDs map[string]struct{}, baseID int64) string {
	for attempt := 0; ; attempt++ {
		id := fmt.Sprintf("settings-import-%d-%d", baseID, attempt)
		if _, exists := existingIDs[id]; !exists {
			existingIDs[id] = struct{}{}
			return id
		}
	}
}

func (a *App) SelectSettingsProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !slices.ContainsFunc(a.state.SettingsProfiles, func(profile model.SettingsProfile) bool { return profile.ID == id }) {
		return a.state, fmt.Errorf("setting profile not found")
	}
	a.state.SelectedSettingsProfileID = id
	return a.saveLocked()
}

func (a *App) ReorderSettingsProfiles(ids []string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reordered, err := reorderProfiles(a.state.SettingsProfiles, ids, func(profile model.SettingsProfile) string {
		return profile.ID
	}, "settings profile")
	if err != nil {
		return a.state, err
	}
	a.state.SettingsProfiles = reordered
	return a.saveLocked()
}

func (a *App) GetDefaultSettingsProfile() model.SettingsProfile {
	return profiles.NormalizeSettingsProfile(model.DefaultSettingsProfile())
}

func (a *App) ValidateResolverText(rawText string) model.ResolverTextValidation {
	return resolver.ValidateText(rawText)
}

func (a *App) GetResolverProfilePreview(id string, offset int, limit int) (model.ResolverPreviewPage, error) {
	a.mu.Lock()
	var profile model.ResolverProfile
	found := false
	for _, candidate := range a.state.ResolverProfiles {
		if candidate.ID == id {
			profile = candidate
			found = true
			break
		}
	}
	a.mu.Unlock()
	if !found {
		return model.ResolverPreviewPage{}, fmt.Errorf("resolver profile not found")
	}
	return profiles.ReadResolverPreviewPage(profile, offset, limit)
}

func (a *App) StartConnection() (model.AppState, error) {
	if a.parallelTestRunning() {
		return a.GetAppState(), fmt.Errorf("parallel test is running")
	}
	a.clearFinishedParallelTest()
	return a.startConnection(context.Background())
}

func (a *App) startConnection(ctx context.Context) (model.AppState, error) {
	return a.startConnectionWithSettingsOptions(ctx, nil, "", "", nil)
}

func (a *App) startConnectionWithSettings(ctx context.Context, overrideSettings *model.SettingsProfile, autoProfilePresetID, autoProfileName string, resolvers []string) (model.AppState, error) {
	return a.startConnectionWithSettingsOptions(ctx, overrideSettings, autoProfilePresetID, autoProfileName, resolvers)
}

func (a *App) startConnectionWithSettingsOptions(ctx context.Context, overrideSettings *model.SettingsProfile, autoProfilePresetID, autoProfileName string, resolvers []string) (model.AppState, error) {
	a.mu.Lock()
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.Status != model.RuntimeFailed {
		defer a.mu.Unlock()
		return a.state, nil
	}
	state := profiles.NormalizeState(a.state)
	configState := state
	if len(resolvers) > 0 {
		configState = stateWithParallelResolvers(configState, resolvers)
	}
	var cfg storm.LaunchConfig
	var err error
	if overrideSettings != nil {
		cfg, err = storm.BuildLaunchConfigWithSettings(configState, *overrideSettings)
	} else {
		cfg, err = storm.BuildLaunchConfig(configState)
	}
	if err != nil {
		a.state.Runtime.Status = model.RuntimeFailed
		a.state.Runtime.RuntimeType = model.RuntimeTypeMasterDNS
		message := brandDisplayText(err.Error())
		a.state.Runtime.Message = message
		a.state.Runtime.ActiveConnectionID = ""
		a.state.Runtime.ListenIP = ""
		a.state.Runtime.ListenPort = 0
		a.state.Runtime.ProxyProtocol = ""
		a.state.Runtime.LocalProxyIP = ""
		a.state.Runtime.PublicProxyIP = ""
		a.state.Runtime.FrontingIP = ""
		a.state.Runtime.ResolverMTUScanPaused = false
		a.state.Runtime.AutoProfilePresetID = ""
		a.state.Runtime.AutoProfileName = ""
		a.state.Runtime.Progress = model.ConnectionProgress{Phase: "failed"}
		a.state.Runtime.TrafficMonitorMessage = ""
		next := a.state
		a.mu.Unlock()
		a.emit("runtime:error", message)
		a.emit("runtime:state", next.Runtime)
		return next, err
	}
	state.Runtime.Status = model.RuntimeConnecting
	state.Runtime.RuntimeType = model.RuntimeTypeMasterDNS
	state.Runtime.Message = "Starting MasterDNS"
	state.Runtime.ActiveConnectionID = cfg.Connection.ID
	state.Runtime.ListenIP = cfg.PublicListenIP
	state.Runtime.ListenPort = cfg.PublicListenPort
	state.Runtime.ProxyProtocol = cfg.CoreProtocol
	state.Runtime.LocalProxyIP, state.Runtime.PublicProxyIP = proxyShareIPs(cfg.PublicListenIP, detectShareNetworkIPv4)
	state.Runtime.FrontingIP = ""
	state.Runtime.ResolverMTUScanPaused = false
	state.Runtime.AutoProfilePresetID = strings.TrimSpace(autoProfilePresetID)
	state.Runtime.AutoProfileName = strings.TrimSpace(autoProfileName)
	state.Runtime.Progress = model.ConnectionProgress{Phase: "preparing", Percent: 3}
	state.Runtime.ResolverState = model.ResolverRuntimeState{}
	state.Runtime.Stats = model.TrafficStats{}
	state.Runtime.TrafficMonitorMessage = ""
	state.Runtime.Logs = []string{"Starting MasterDNS"}
	state.Runtime.MasterDNSLogs = appendRuntimeLog([]string{"Starting MasterDNS"}, state.Runtime.MasterDNSLogs...)
	a.state = state
	next := a.state
	a.mu.Unlock()

	a.clearProxyCountryCache()
	a.emit("runtime:state", next.Runtime)
	a.emit("runtime:progress", next.Runtime.Progress)
	a.notifyFirewallIfEnabled(ctx)
	if err := a.manager.Start(ctx, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
			return a.GetAppState(), nil
		}
		a.handleRuntimeError(err.Error())
		a.handleRuntimeState(model.RuntimeFailed, err.Error())
		return a.GetAppState(), err
	}
	return a.GetAppState(), nil
}

func (a *App) StopConnection() (model.AppState, error) {
	err := a.manager.Stop()
	if err == nil {
		a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	}
	return a.GetAppState(), err
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

func (a *App) SetResolverMTUScanPaused(paused bool) (model.AppState, error) {
	a.mu.Lock()
	if a.state.Runtime.Status != model.RuntimeConnected {
		next := a.state
		a.mu.Unlock()
		return next, fmt.Errorf("resolver MTU scanning can only be changed while connected")
	}
	a.mu.Unlock()

	if err := a.manager.SetResolverMTUScanPaused(paused); err != nil {
		return a.GetAppState(), err
	}

	a.mu.Lock()
	a.state.Runtime.ResolverMTUScanPaused = paused
	runtimeState := a.state.Runtime
	next := a.state
	a.mu.Unlock()
	a.emit("runtime:state", runtimeState)
	return next, nil
}

func (a *App) ExportClientToml() (string, error) {
	a.mu.Lock()
	state := a.state
	a.mu.Unlock()
	settings, ok := storm.SelectedSettings(state)
	if !ok {
		return "", fmt.Errorf("settings profile is missing")
	}
	return storm.RenderExportClientTOML(settings), nil
}

func (a *App) ExportConnectionProfileLink(profile model.ConnectionProfile) (string, error) {
	return profiles.ExportConnectionProfile(profile)
}

func (a *App) ExportAllConnectionProfileLinks() (string, error) {
	a.mu.Lock()
	connectionProfiles := append([]model.ConnectionProfile(nil), a.state.ConnectionProfiles...)
	a.mu.Unlock()
	return profiles.ExportConnectionProfiles(connectionProfiles)
}

func (a *App) ExportSettingsProfileToml(profile model.SettingsProfile) (string, error) {
	return storm.RenderExportClientTOML(profile), nil
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
	a.state = next
	return a.state, nil
}

func (a *App) Quit() {
	a.shutdown(context.Background())
	if a.ctx != nil {
		wailsruntime.Quit(a.ctx)
	}
}

func (a *App) applyResolverToSelectedConnectionLocked(resolverID string) {
	for idx := range a.state.ConnectionProfiles {
		if a.state.ConnectionProfiles[idx].ID == a.state.SelectedConnectionProfileID {
			a.state.ConnectionProfiles[idx].ResolverProfileID = resolverID
			return
		}
	}
}

func (a *App) connectionSelectionLockedLocked() bool {
	switch a.state.Runtime.Status {
	case "", model.RuntimeDisconnected, model.RuntimeFailed:
		return false
	default:
		return true
	}
}

func (a *App) resolverSelectionLockedLocked() bool {
	switch a.state.Runtime.Status {
	case "", model.RuntimeDisconnected, model.RuntimeFailed:
		return false
	default:
		return true
	}
}

func (a *App) resolverProfileIsEffectiveLocked(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	connectionIDs := []string{a.state.Runtime.ActiveConnectionID, a.state.SelectedConnectionProfileID}
	for _, connectionID := range connectionIDs {
		if a.effectiveResolverIDForConnectionLocked(connectionID) == id {
			return true
		}
	}
	return a.state.Runtime.ActiveConnectionID == "" &&
		a.state.SelectedConnectionProfileID == "" &&
		a.state.SelectedResolverProfileID == id
}

func (a *App) effectiveResolverIDForConnectionLocked(connectionID string) string {
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		return ""
	}
	resolverID := a.state.SelectedResolverProfileID
	for _, profile := range a.state.ConnectionProfiles {
		if profile.ID == connectionID {
			if profile.ResolverProfileID != "" {
				resolverID = profile.ResolverProfileID
			}
			break
		}
	}
	return resolverID
}

func (a *App) uniqueResolverProfileIDLocked(prefix string) string {
	base := time.Now().UnixNano()
	for attempt := 0; ; attempt++ {
		id := fmt.Sprintf("%s-%d", prefix, base)
		if attempt > 0 {
			id = fmt.Sprintf("%s-%d-%d", prefix, base, attempt)
		}
		if !slices.ContainsFunc(a.state.ResolverProfiles, func(profile model.ResolverProfile) bool { return profile.ID == id }) {
			return id
		}
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
	message = brandDisplayText(message)
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

func (a *App) handleResolverState(state model.ResolverRuntimeState) {
	a.mu.Lock()
	if !a.acceptsLiveRuntimeUpdateLocked() {
		a.mu.Unlock()
		return
	}
	a.state.Runtime.ResolverState = state
	runtimeState := a.state.Runtime
	a.mu.Unlock()
	a.emit("runtime:resolvers", state)
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
	message = strings.TrimSpace(brandDisplayText(message))
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
	message = brandDisplayText(strings.TrimSpace(message))
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
	line = brandDisplayText(strings.TrimSpace(line))
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

func brandDisplayText(text string) string {
	const source = "StormDNS"
	const display = "MasterDNS/StormDNS"
	if !strings.Contains(text, source) {
		return text
	}
	var out strings.Builder
	out.Grow(len(text) + len(display) - len(source))
	for {
		idx := strings.Index(text, source)
		if idx == -1 {
			out.WriteString(text)
			return out.String()
		}
		prefix := text[:idx]
		out.WriteString(prefix)
		if strings.HasSuffix(prefix, "MasterDNS/") {
			out.WriteString(source)
		} else {
			out.WriteString(display)
		}
		text = text[idx+len(source):]
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
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, name, payload)
}

func appConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "WhiteDNS Desktop"), nil
}

func findMasterDNSSourceDir() string {
	candidates := make([]string, 0)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "MasterDnsVPN"),
			filepath.Join(cwd, "..", "MasterDnsVPN"),
			filepath.Join(cwd, "..", "..", "MasterDnsVPN"),
		)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "MasterDnsVPN"),
			filepath.Join(dir, "..", "MasterDnsVPN"),
			filepath.Join(dir, "..", "..", "MasterDnsVPN"),
		)
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "cmd", "client", "main.go")); err == nil {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

func findClientsDir() string {
	for _, candidate := range appRelativeDirs("clients") {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

func findXrayCoresDir() string {
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
	if envDir := strings.TrimSpace(os.Getenv("WHITEDNS_CLIENTS_DIR")); envDir != "" && name == "clients" {
		candidates = append(candidates, envDir)
	}
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

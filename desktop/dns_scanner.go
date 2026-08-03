package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/resolver"
	runtimemgr "whitevpn-desktop/internal/runtime"
	"whitevpn-desktop/internal/storm"
)

const (
	defaultDNSScannerParallel  = 200
	maxDNSScannerParallel      = 1000
	maxDNSScannerRangeHosts    = 65536
	dnsScannerRuntimeDirName   = "dns-scanner"
	dnsScannerInputDirName     = "scanner-inputs"
	dnsScannerResultDirName    = "scanner-results"
	dnsScannerSnapshotFileName = "last-scan.json"
	dnsScannerResultsFileName  = "last-valid.resolvers"
	dnsScannerResolverIDPrefix = "resolver-scanner"
	dnsScannerReportEnv        = "WHITEDNS_SCANNER_REPORT_FILE"
	dnsScannerInputEnv         = "WHITEDNS_SCANNER_INPUT_FILE"
	dnsScannerModeManual       = "manual"
	dnsScannerModeUpgrade      = "connection-upgrade"

	connectionUpgradeScannerMessage = "VPN is connected while scanning resolvers in the background. When the scan finishes, choose whether to restart with the best resolvers found."
)

type scannerInputSummary struct {
	Path       string
	FileName   string
	Total      int
	Invalid    int
	Duplicates int
}

type scannerPersistedSnapshot struct {
	Version   int                `json:"version"`
	InputPath string             `json:"inputPath"`
	State     model.ScannerState `json:"state"`
	UpdatedAt int64              `json:"updatedAt"`
}

type connectionUpgradeScanPlan struct {
	Connection             model.ConnectionProfile
	Settings               model.SettingsProfile
	BootstrapResolvers     []string
	CandidateResolvers     []string
	CandidateInputPath     string
	CandidateInputFileName string
	CandidateTotal         int
	CandidateInvalid       int
	CandidateDuplicates    int
	ScanParallel           int
	AutoRestart            bool
}

func (a *App) GetScannerState() model.ScannerState {
	a.scannerMu.Lock()
	defer a.scannerMu.Unlock()
	return cloneScannerState(a.scannerState)
}

func (a *App) SelectScannerInputFile() (model.ScannerState, error) {
	if a.ctx == nil {
		return a.GetScannerState(), fmt.Errorf("file picker is unavailable")
	}
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		return state, fmt.Errorf("cancel the active DNS scan before choosing a new file")
	}
	a.scannerMu.Unlock()

	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select DNS scanner input file",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Resolver lists (*.txt, *.csv, *.lst)", Pattern: "*.txt;*.csv;*.lst;*.resolvers"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return a.GetScannerState(), err
	}
	if strings.TrimSpace(path) == "" {
		return a.GetScannerState(), nil
	}

	summary, err := a.normalizeScannerInputFile(path)
	if err != nil {
		return a.GetScannerState(), err
	}

	a.scannerMu.Lock()
	oldInput := a.scannerInputPath
	a.scannerInputPath = summary.Path
	a.scannerInputStarted = false
	next := cloneScannerState(a.scannerState)
	next.Status = model.ScannerIdle
	next.Mode = dnsScannerModeManual
	next.Paused = false
	next.Phase = "ready"
	next.Message = "Ready to scan"
	next.InputFileName = summary.FileName
	next.BootstrapResolverCount = 0
	next.RestartAvailable = false
	next.ScannedResolverCount = 0
	next.Total = summary.Total
	next.Completed = 0
	next.Valid = 0
	next.Rejected = 0
	next.Invalid = summary.Invalid
	next.Duplicates = summary.Duplicates
	next.ValidResolvers = nil
	next.Error = ""
	next.StartedAt = 0
	next.FinishedAt = 0
	if next.ScanParallel <= 0 {
		next.ScanParallel = defaultDNSScannerParallel
	}
	if next.SelectedConnectionProfileID == "" {
		next.SelectedConnectionProfileID = a.selectedConnectionProfileID()
	}
	a.scannerState = next
	a.resetScannerResultsFileLocked()
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	if oldInput != "" && oldInput != summary.Path {
		_ = os.Remove(oldInput)
	}
	a.emit("scanner:state", state)
	return state, nil
}

func (a *App) StartScannerScan(request model.ScannerStartRequest) (model.ScannerState, error) {
	scanParallel := normalizeDNSScannerParallel(request.ScanParallel)
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		return state, fmt.Errorf("DNS scanner is already running")
	}
	inputPath := strings.TrimSpace(a.scannerInputPath)
	inputFileName := a.scannerState.InputFileName
	inputTotal := a.scannerState.Total
	inputInvalid := a.scannerState.Invalid
	inputDuplicates := a.scannerState.Duplicates
	a.scannerMu.Unlock()
	if inputPath == "" {
		return a.GetScannerState(), fmt.Errorf("choose a DNS scanner input file first")
	}
	if inputTotal <= 0 {
		return a.GetScannerState(), fmt.Errorf("scanner input file contains no valid DNS resolvers")
	}

	connection, err := a.scannerConnection(request.ConnectionProfileID)
	if err != nil {
		return a.GetScannerState(), err
	}
	listenPort, apiPort, err := scannerRandomPorts()
	if err != nil {
		return a.GetScannerState(), err
	}
	runtimeDir, err := newDNSScannerRuntimeDir()
	if err != nil {
		return a.GetScannerState(), err
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			_ = os.RemoveAll(runtimeDir)
		}
	}()

	manager := runtimemgr.NewManager(runtimeManagerOptions(runtimeDir), runtimemgr.Callbacks{})
	binaryPath, err := manager.ResolveClientBinary(context.Background())
	if err != nil {
		return a.GetScannerState(), err
	}

	launchID := fmt.Sprintf("%d", time.Now().UnixNano())
	configFile := filepath.Join(runtimeDir, ".wd-scanner-"+launchID+".toml")
	controlFile := filepath.Join(runtimeDir, ".wd-scanner-"+launchID+".mtu-scan-control")
	bootstrapResolversFile, err := a.scannerBootstrapResolverFile(connection.ID, runtimeDir)
	if err != nil {
		return a.GetScannerState(), err
	}
	clientTOML := storm.RenderScannerClientTOML(connection, listenPort, apiPort, scanParallel)
	if err := os.WriteFile(configFile, []byte(clientTOML), 0o600); err != nil {
		return a.GetScannerState(), err
	}
	if err := os.WriteFile(controlFile, []byte("resume\n"), 0o600); err != nil {
		return a.GetScannerState(), err
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		cancel()
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		return state, fmt.Errorf("DNS scanner is already running")
	}
	a.scannerRunID++
	runID := a.scannerRunID
	a.scannerAutoApplyStarted = false
	a.scannerCancel = cancel
	a.scannerControlFile = controlFile
	a.scannerRuntimeDir = runtimeDir
	a.scannerInputStarted = false
	a.scannerState = model.ScannerState{
		Status:                      model.ScannerRunning,
		Mode:                        dnsScannerModeManual,
		Phase:                       "starting",
		Message:                     "Starting DNS scanner",
		SelectedConnectionProfileID: connection.ID,
		InputFileName:               inputFileName,
		ScanParallel:                scanParallel,
		BootstrapResolverCount:      0,
		RestartAvailable:            false,
		ScannedResolverCount:        0,
		Total:                       inputTotal,
		Invalid:                     inputInvalid,
		Duplicates:                  inputDuplicates,
		ValidResolvers:              []string{},
		StartedAt:                   time.Now().UnixMilli(),
	}
	a.resetScannerResultsFileLocked()
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	cleanupOnError = false
	a.emit("scanner:state", state)

	go a.runDNSScannerProcess(ctx, runID, binaryPath, configFile, bootstrapResolversFile, inputPath, controlFile, a.scannerResultsPath, runtimeDir)
	return state, nil
}

func (a *App) startConnectionUpgradeScanner(plan connectionUpgradeScanPlan) {
	if err := a.startConnectionUpgradeScannerRun(plan); err != nil {
		a.failConnectionUpgradeScanner(plan, err)
	}
}

func (a *App) startConnectionUpgradeScannerRun(plan connectionUpgradeScanPlan) error {
	scanParallel := normalizeDNSScannerParallel(plan.ScanParallel)
	if plan.CandidateTotal <= 0 {
		if len(plan.CandidateResolvers) > 0 {
			plan.CandidateTotal = len(plan.CandidateResolvers)
		} else {
			return fmt.Errorf("background resolver scan has no resolver candidates")
		}
	}
	if len(plan.BootstrapResolvers) == 0 {
		return fmt.Errorf("background resolver scan has no bootstrap resolvers")
	}

	runtimeDir, err := newDNSScannerRuntimeDir()
	if err != nil {
		return err
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			_ = os.RemoveAll(runtimeDir)
		}
	}()

	manager := runtimemgr.NewManager(runtimeManagerOptions(runtimeDir), runtimemgr.Callbacks{})
	binaryPath, err := manager.ResolveClientBinary(context.Background())
	if err != nil {
		return err
	}

	launchID := fmt.Sprintf("%d", time.Now().UnixNano())
	configFile := filepath.Join(runtimeDir, ".wd-scanner-"+launchID+".toml")
	controlFile := filepath.Join(runtimeDir, ".wd-scanner-"+launchID+".mtu-scan-control")
	bootstrapResolversFile := filepath.Join(runtimeDir, "bootstrap-resolvers.txt")
	if err := os.WriteFile(bootstrapResolversFile, []byte(strings.Join(plan.BootstrapResolvers, "\n")+"\n"), 0o600); err != nil {
		return err
	}

	inputPath := strings.TrimSpace(plan.CandidateInputPath)
	if inputPath == "" {
		inputPath = filepath.Join(runtimeDir, "connection-upgrade-input.resolvers")
		if err := os.WriteFile(inputPath, []byte(strings.Join(plan.CandidateResolvers, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	} else if info, err := os.Stat(inputPath); err != nil || info.IsDir() {
		return fmt.Errorf("background resolver scan input file is unavailable")
	}

	listenPort, apiPort, err := scannerRandomPorts()
	if err != nil {
		return err
	}
	clientTOML := storm.RenderConnectionUpgradeScannerClientTOML(plan.Connection, plan.Settings, listenPort, apiPort, scanParallel)
	if err := os.WriteFile(configFile, []byte(clientTOML), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(controlFile, []byte("resume\n"), 0o600); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		cancel()
		a.scannerMu.Unlock()
		return fmt.Errorf("DNS scanner is already running")
	}
	a.scannerRunID++
	runID := a.scannerRunID
	a.scannerAutoApplyStarted = false
	a.scannerCancel = cancel
	a.scannerControlFile = controlFile
	a.scannerRuntimeDir = runtimeDir
	a.scannerInputStarted = false
	a.scannerState = model.ScannerState{
		Status:                      model.ScannerRunning,
		Mode:                        dnsScannerModeUpgrade,
		Phase:                       "starting",
		Message:                     connectionUpgradeScannerMessage,
		SelectedConnectionProfileID: plan.Connection.ID,
		InputFileName:               plan.CandidateInputFileName,
		ScanParallel:                scanParallel,
		BootstrapResolverCount:      len(plan.BootstrapResolvers),
		RestartAvailable:            false,
		AutoRestart:                 plan.AutoRestart,
		ScannedResolverCount:        0,
		Total:                       plan.CandidateTotal,
		Invalid:                     plan.CandidateInvalid,
		Duplicates:                  plan.CandidateDuplicates,
		ValidResolvers:              []string{},
		StartedAt:                   time.Now().UnixMilli(),
	}
	a.resetScannerResultsFileLocked()
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	cleanupOnError = false
	a.emit("scanner:state", state)

	go a.runDNSScannerProcess(ctx, runID, binaryPath, configFile, bootstrapResolversFile, inputPath, controlFile, a.scannerResultsPath, runtimeDir)
	return nil
}

func (a *App) failConnectionUpgradeScanner(plan connectionUpgradeScanPlan, err error) {
	a.scannerMu.Lock()
	if a.scannerState.Status != model.ScannerRunning {
		a.scannerRunID++
		a.scannerState = model.ScannerState{
			Status:                      model.ScannerFailed,
			Mode:                        dnsScannerModeUpgrade,
			Phase:                       "failed",
			Message:                     "Background resolver scan failed",
			SelectedConnectionProfileID: plan.Connection.ID,
			InputFileName:               plan.CandidateInputFileName,
			ScanParallel:                normalizeDNSScannerParallel(plan.ScanParallel),
			BootstrapResolverCount:      len(plan.BootstrapResolvers),
			AutoRestart:                 plan.AutoRestart,
			Total:                       plan.CandidateTotal,
			Error:                       err.Error(),
			FinishedAt:                  time.Now().UnixMilli(),
		}
	} else {
		a.scannerState.Status = model.ScannerFailed
		a.scannerState.Phase = "failed"
		a.scannerState.Message = "Background resolver scan failed"
		a.scannerState.Error = err.Error()
		a.scannerState.FinishedAt = time.Now().UnixMilli()
	}
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
}

func (a *App) SetScannerPaused(paused bool) (model.ScannerState, error) {
	a.scannerMu.Lock()
	if a.scannerState.Status != model.ScannerRunning {
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		return state, fmt.Errorf("DNS scanner is not running")
	}
	controlFile := a.scannerControlFile
	a.scannerMu.Unlock()
	if strings.TrimSpace(controlFile) == "" {
		return a.GetScannerState(), fmt.Errorf("DNS scanner pause control is unavailable")
	}

	value := "resume\n"
	message := "DNS scanner running"
	if paused {
		value = "pause\n"
		message = "DNS scanner paused"
	}
	if err := os.WriteFile(controlFile, []byte(value), 0o600); err != nil {
		return a.GetScannerState(), err
	}

	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		a.scannerState.Paused = paused
		if a.scannerState.Mode == dnsScannerModeUpgrade {
			if paused {
				a.scannerState.Message = "Background resolver scan paused. VPN remains connected."
			} else {
				a.scannerState.Message = connectionUpgradeScannerMessage
			}
		} else {
			a.scannerState.Message = message
		}
	}
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
	return state, nil
}

func (a *App) CancelScannerScan() (model.ScannerState, error) {
	a.scannerMu.Lock()
	if a.scannerCancel != nil {
		a.scannerCancel()
		a.scannerCancel = nil
	}
	if a.scannerState.Status == model.ScannerRunning {
		_ = a.refreshScannerValidResolversLocked()
		a.scannerState.Status = model.ScannerCancelled
		a.scannerState.Paused = false
		a.scannerState.RestartAvailable = false
		a.scannerState.Message = "DNS scanner cancelled"
		a.scannerState.FinishedAt = time.Now().UnixMilli()
	}
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
	return state, nil
}

func (a *App) ClearScannerResults() (model.ScannerState, error) {
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		return state, fmt.Errorf("cancel the active DNS scan before clearing results")
	}
	inputPath := a.scannerInputPath
	a.scannerInputPath = ""
	a.scannerInputStarted = false
	a.scannerAutoApplyStarted = false
	a.scannerState = model.ScannerState{
		Status:       model.ScannerIdle,
		Mode:         dnsScannerModeManual,
		ScanParallel: defaultDNSScannerParallel,
	}
	a.clearScannerPersistenceLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	if inputPath != "" {
		_ = os.Remove(inputPath)
	}
	a.emit("scanner:state", state)
	return state, nil
}

func (a *App) SaveScannerResolverProfile(name string) (model.ResolverImportResult, error) {
	a.scannerMu.Lock()
	if err := a.refreshScannerValidResolversLocked(); err != nil {
		a.scannerMu.Unlock()
		return model.ResolverImportResult{State: a.GetAppState()}, err
	}
	validResolvers := append([]string(nil), a.scannerState.ValidResolvers...)
	a.scannerMu.Unlock()
	if len(validResolvers) == 0 {
		return model.ResolverImportResult{State: a.GetAppState()}, fmt.Errorf("no valid DNS resolvers to save")
	}

	profile, err := a.store.CreateManagedResolverProfile(name, dnsScannerResolverIDPrefix, strings.NewReader(strings.Join(validResolvers, "\n")))
	if err != nil {
		return model.ResolverImportResult{State: a.GetAppState()}, err
	}

	a.mu.Lock()
	a.state = profiles.NormalizeStatePreservingRuntime(a.state)
	a.state.ResolverProfiles = append(a.state.ResolverProfiles, profile)
	if !a.resolverSelectionLockedLocked() {
		a.state.SelectedResolverProfileID = profile.ID
		a.applyResolverToSelectedConnectionLocked(profile.ID)
	}
	next, err := a.saveLocked()
	a.mu.Unlock()
	return model.ResolverImportResult{
		State:    next,
		Profile:  profile,
		Imported: profile.ResolverCount,
		Skipped:  len(validResolvers) - profile.ResolverCount + profile.ResolverInvalidCount,
	}, err
}

func (a *App) ApplyScannerConnectionUpgrade(action string) (model.AppState, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "save" && action != "runtime" {
		return a.GetAppState(), fmt.Errorf("unknown scanner upgrade action")
	}

	a.scannerMu.Lock()
	if a.scannerState.Mode != dnsScannerModeUpgrade || !a.scannerState.RestartAvailable {
		a.scannerMu.Unlock()
		return a.GetAppState(), fmt.Errorf("no completed background resolver scan is ready to apply")
	}
	if err := a.refreshScannerValidResolversLocked(); err != nil {
		a.scannerMu.Unlock()
		return a.GetAppState(), err
	}
	validResolvers := append([]string(nil), a.scannerState.ValidResolvers...)
	connectionID := strings.TrimSpace(a.scannerState.SelectedConnectionProfileID)
	a.scannerState.RestartAvailable = false
	a.scannerState.AutoRestart = false
	a.scannerState.Message = "Restarting VPN with scanned resolvers."
	a.scannerState.Error = ""
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
	if len(validResolvers) == 0 {
		return a.GetAppState(), fmt.Errorf("no valid DNS resolvers to apply")
	}

	if action == "save" {
		profile, err := a.store.CreateManagedResolverProfile("Scanned DNS Resolvers", dnsScannerResolverIDPrefix, strings.NewReader(strings.Join(validResolvers, "\n")))
		if err != nil {
			return a.GetAppState(), err
		}
		a.mu.Lock()
		a.state = profiles.NormalizeStatePreservingRuntime(a.state)
		a.state.ResolverProfiles = append(a.state.ResolverProfiles, profile)
		a.state.SelectedConnectionProfileID = selectedConnectionIDOrCurrent(a.state, connectionID)
		a.state.SelectedResolverProfileID = profile.ID
		for idx := range a.state.ConnectionProfiles {
			if a.state.ConnectionProfiles[idx].ID == a.state.SelectedConnectionProfileID {
				a.state.ConnectionProfiles[idx].ResolverProfileID = profile.ID
				break
			}
		}
		_, err = a.saveLocked()
		a.mu.Unlock()
		if err != nil {
			return a.GetAppState(), err
		}
	} else {
		a.mu.Lock()
		a.state = profiles.NormalizeStatePreservingRuntime(a.state)
		a.state.SelectedConnectionProfileID = selectedConnectionIDOrCurrent(a.state, connectionID)
		_, err := a.saveLocked()
		a.mu.Unlock()
		if err != nil {
			return a.GetAppState(), err
		}
	}

	if a.manager != nil {
		if err := a.manager.Stop(); err != nil {
			a.markScannerUpgradeRestartFailed(err)
			return a.GetAppState(), err
		}
		a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	}
	next, err := a.startConnectionWithSettingsOptions(context.Background(), nil, "", "", validResolvers)
	if err != nil {
		a.markScannerUpgradeRestartFailed(err)
		return next, err
	}

	a.scannerMu.Lock()
	a.scannerState.RestartAvailable = false
	a.scannerState.Message = scannerUpgradeAppliedMessage(action, len(validResolvers))
	a.scannerState.Error = ""
	a.persistScannerSnapshotLocked()
	scannerState := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", scannerState)
	return next, nil
}

func (a *App) DismissScannerConnectionUpgrade() (model.ScannerState, error) {
	a.scannerMu.Lock()
	if a.scannerState.Mode != dnsScannerModeUpgrade || !a.scannerState.RestartAvailable {
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		return state, nil
	}
	a.scannerState.RestartAvailable = false
	a.scannerState.Message = "Keeping the current VPN session."
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
	return state, nil
}

func selectedConnectionIDOrCurrent(state model.AppState, connectionID string) string {
	connectionID = strings.TrimSpace(connectionID)
	if connectionID != "" {
		for _, profile := range state.ConnectionProfiles {
			if profile.ID == connectionID {
				return connectionID
			}
		}
	}
	return state.SelectedConnectionProfileID
}

func scannerUpgradeAppliedMessage(action string, count int) string {
	if action == "save" {
		return fmt.Sprintf("Saved %d scanned resolver%s and restarted the VPN.", count, pluralSuffix(count))
	}
	return fmt.Sprintf("Restarted the VPN once with %d scanned resolver%s.", count, pluralSuffix(count))
}

func (a *App) markScannerUpgradeRestartFailed(err error) {
	a.scannerMu.Lock()
	a.scannerAutoApplyStarted = false
	a.scannerState.RestartAvailable = true
	a.scannerState.AutoRestart = false
	a.scannerState.Error = err.Error()
	a.scannerState.Message = "VPN restart with scanned resolvers failed"
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
}

func (a *App) runDNSScannerProcess(ctx context.Context, runID int64, binaryPath string, configFile string, bootstrapResolversFile string, scannerInputFile string, controlFile string, reportFile string, runtimeDir string) {
	defer os.RemoveAll(runtimeDir)

	cmd := exec.CommandContext(ctx, binaryPath, dnsScannerCommandArgs(configFile, bootstrapResolversFile)...)
	hideConsoleWindow(cmd)
	cmd.Dir = runtimeDir
	cmd.Env = append(os.Environ(),
		"WHITEDNS_MTU_SCAN_CONTROL_FILE="+controlFile,
		dnsScannerReportEnv+"="+reportFile,
		dnsScannerInputEnv+"="+scannerInputFile,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.finishDNSScannerRun(runID, model.ScannerFailed, err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		a.finishDNSScannerRun(runID, model.ScannerFailed, err.Error())
		return
	}

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024), 1024*1024)
		for scanner.Scan() {
			a.handleDNSScannerLogLine(runID, scanner.Text())
		}
	}()

	err = cmd.Wait()
	<-outputDone
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		a.finishDNSScannerRun(runID, model.ScannerCancelled, "DNS scanner cancelled")
	case err != nil:
		a.finishDNSScannerRun(runID, model.ScannerFailed, err.Error())
	default:
		a.finishDNSScannerRun(runID, model.ScannerCompleted, "DNS scanner completed")
	}
}

func (a *App) handleDNSScannerLogLine(runID int64, line string) {
	if event, ok := storm.ParseScannerEvent(line); ok {
		a.applyDNSScannerEvent(runID, event)
		return
	}
	if resolvers, ok := storm.ParseResolverState(line); ok {
		a.applyDNSScannerResolverState(runID, resolvers)
		return
	}
	if progress, ok := storm.ParseProgress(line); ok {
		a.scannerMu.Lock()
		if a.scannerRunID == runID && a.scannerState.Status == model.ScannerRunning {
			if !a.scannerInputStarted {
				a.scannerState.Phase = "connecting"
				a.scannerState.Message = dnsScannerConnectingMessage(a.scannerState.Mode)
				a.persistScannerSnapshotLocked()
				state := cloneScannerState(a.scannerState)
				a.scannerMu.Unlock()
				a.emit("scanner:state", state)
				return
			}
			if !dnsScannerProgressBelongsToInputScan(progress, a.scannerState.Total) {
				a.scannerMu.Unlock()
				return
			}
			if progress.Phase != "" {
				a.scannerState.Phase = progress.Phase
			}
			if progress.Total > 0 {
				a.scannerState.Total = progress.Total
			}
			if progress.Completed >= 0 {
				a.scannerState.Completed = progress.Completed
			}
			a.scannerState.ScannedResolverCount = a.scannerState.Completed
			if progress.Valid >= 0 {
				a.scannerState.Valid = progress.Valid
			}
			if progress.Rejected >= 0 {
				a.scannerState.Rejected = progress.Rejected
			}
			_ = a.refreshScannerValidResolversLocked()
			a.scannerState.Message = dnsScannerProgressMessage(a.scannerState)
			a.persistScannerSnapshotLocked()
			state := cloneScannerState(a.scannerState)
			a.scannerMu.Unlock()
			a.emit("scanner:state", state)
			return
		}
		a.scannerMu.Unlock()
	}
}

func (a *App) applyDNSScannerResolverState(runID int64, resolvers model.ResolverRuntimeState) {
	var cancel context.CancelFunc
	a.scannerMu.Lock()
	if a.scannerRunID != runID || a.scannerState.Status != model.ScannerRunning {
		a.scannerMu.Unlock()
		return
	}
	if !a.scannerInputStarted {
		a.scannerState.Phase = "connecting"
		a.scannerState.Message = dnsScannerConnectingMessage(a.scannerState.Mode)
		a.persistScannerSnapshotLocked()
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		a.emit("scanner:state", state)
		return
	}
	if !dnsScannerResolverStateBelongsToInputScan(resolvers, a.scannerState.Total) {
		a.scannerMu.Unlock()
		return
	}
	if resolvers.TotalCount > 0 {
		a.scannerState.Total = resolvers.TotalCount
	}
	if resolvers.ValidCount >= 0 {
		a.scannerState.Valid = resolvers.ValidCount
	}
	if resolvers.RejectedCount >= 0 {
		a.scannerState.Rejected = resolvers.RejectedCount
	}
	completed := resolvers.ValidCount + resolvers.RejectedCount
	if resolvers.TotalCount > 0 && resolvers.PendingCount >= 0 {
		completed = resolvers.TotalCount - resolvers.PendingCount
		if tested := resolvers.ValidCount + resolvers.RejectedCount; tested > completed {
			completed = tested
		}
	}
	if completed >= 0 {
		a.scannerState.Completed = completed
	}
	a.scannerState.ScannedResolverCount = a.scannerState.Completed
	reportErr := a.refreshScannerValidResolversLocked()
	if reportErr != nil {
		a.scannerState.Error = reportErr.Error()
		a.scannerState.Message = "DNS scanner could not read valid resolver report"
	} else if len(a.scannerState.ValidResolvers) > a.scannerState.Valid {
		a.scannerState.Valid = len(a.scannerState.ValidResolvers)
	}

	if dnsScannerResolverStateComplete(resolvers) && reportErr != nil {
		a.scannerState.Status = model.ScannerFailed
		a.scannerState.Paused = false
		a.scannerState.Error = reportErr.Error()
		a.scannerState.FinishedAt = time.Now().UnixMilli()
		cancel = a.scannerCancel
		a.scannerCancel = nil
		a.scannerControlFile = ""
		a.scannerRuntimeDir = ""
	} else if dnsScannerResolverStateComplete(resolvers) {
		a.scannerState.Status = model.ScannerCompleted
		a.scannerState.Paused = false
		a.scannerState.Phase = "mtu"
		a.scannerState.Error = ""
		a.scannerState.Completed = a.scannerState.Total
		a.scannerState.ScannedResolverCount = a.scannerState.Completed
		a.finalizeScannerCompletedCountsLocked()
		a.applyScannerCompletionMessageLocked()
		a.scannerState.FinishedAt = time.Now().UnixMilli()
		cancel = a.scannerCancel
		a.scannerCancel = nil
		a.scannerControlFile = ""
		a.scannerRuntimeDir = ""
	} else {
		a.scannerState.Phase = "mtu"
		a.scannerState.Message = dnsScannerProgressMessage(a.scannerState)
	}
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
	if cancel != nil {
		cancel()
	}
}

func (a *App) applyDNSScannerEvent(runID int64, event storm.ScannerEvent) {
	a.scannerMu.Lock()
	if a.scannerRunID != runID || a.scannerState.Status != model.ScannerRunning {
		a.scannerMu.Unlock()
		return
	}
	switch event.Event {
	case "started":
		a.scannerInputStarted = true
		a.scannerState.Phase = "mtu"
		a.scannerState.Message = dnsScannerProgressMessage(a.scannerState)
		if event.Total > 0 {
			a.scannerState.Total = event.Total
			a.scannerState.Message = dnsScannerProgressMessage(a.scannerState)
		}
		a.scannerState.Completed = 0
		a.scannerState.ScannedResolverCount = 0
		a.scannerState.Valid = 0
		a.scannerState.Rejected = 0
		a.scannerState.ValidResolvers = []string{}
		a.scannerState.Error = ""
	case "valid":
		if event.Resolver != "" && !containsString(a.scannerState.ValidResolvers, event.Resolver) {
			if err := a.appendScannerValidResolverLocked(event.Resolver); err != nil {
				a.scannerState.Status = model.ScannerFailed
				a.scannerState.Paused = false
				a.scannerState.Error = err.Error()
				a.scannerState.Message = "DNS scanner failed to save partial results"
				a.scannerState.FinishedAt = time.Now().UnixMilli()
				if a.scannerCancel != nil {
					a.scannerCancel()
					a.scannerCancel = nil
				}
				a.persistScannerSnapshotLocked()
				state := cloneScannerState(a.scannerState)
				a.scannerMu.Unlock()
				a.emit("scanner:state", state)
				return
			}
			a.scannerState.ValidResolvers = append(a.scannerState.ValidResolvers, event.Resolver)
		}
		if len(a.scannerState.ValidResolvers) > a.scannerState.Valid {
			a.scannerState.Valid = len(a.scannerState.ValidResolvers)
		}
	case "rejected":
		a.scannerState.Message = "DNS resolver rejected"
	case "complete":
		if event.Total > 0 {
			a.scannerState.Total = event.Total
			a.scannerState.Completed = event.Total
			a.scannerState.ScannedResolverCount = event.Total
		}
		if event.Valid > 0 || event.Rejected > 0 {
			a.scannerState.Valid = event.Valid
			a.scannerState.Rejected = event.Rejected
		}
	}
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	go a.emit("scanner:state", state)
}

func (a *App) finishDNSScannerRun(runID int64, status string, message string) {
	a.scannerMu.Lock()
	if a.scannerRunID != runID {
		a.scannerMu.Unlock()
		return
	}
	a.scannerCancel = nil
	a.scannerControlFile = ""
	a.scannerRuntimeDir = ""
	if a.scannerState.Status != model.ScannerRunning {
		a.persistScannerSnapshotLocked()
		state := cloneScannerState(a.scannerState)
		a.scannerMu.Unlock()
		a.emit("scanner:state", state)
		return
	}
	_ = a.refreshScannerValidResolversLocked()
	a.scannerState.Status = status
	if status == model.ScannerFailed {
		a.scannerState.Status = status
		a.scannerState.Error = message
	}
	a.scannerState.Paused = false
	if message != "" {
		a.scannerState.Message = message
	}
	if a.scannerState.Total > 0 && a.scannerState.Completed > a.scannerState.Total {
		a.scannerState.Completed = a.scannerState.Total
	}
	if a.scannerState.Status == model.ScannerCompleted && a.scannerState.Completed < a.scannerState.Total {
		a.scannerState.Completed = a.scannerState.Total
	}
	a.scannerState.ScannedResolverCount = a.scannerState.Completed
	if a.scannerState.Status == model.ScannerCompleted {
		a.finalizeScannerCompletedCountsLocked()
		a.applyScannerCompletionMessageLocked()
	}
	a.scannerState.FinishedAt = time.Now().UnixMilli()
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	a.emit("scanner:state", state)
}

func scannerPersistencePaths(configDir string) (string, string, error) {
	dir := filepath.Join(configDir, dnsScannerResultDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, dnsScannerSnapshotFileName), filepath.Join(dir, dnsScannerResultsFileName), nil
}

func loadPersistedScannerSnapshot(snapshotPath string, resultsPath string) (model.ScannerState, string, bool) {
	var snapshot scannerPersistedSnapshot
	snapshotLoaded := false
	if raw, err := os.ReadFile(snapshotPath); err == nil {
		if err := json.Unmarshal(raw, &snapshot); err == nil {
			snapshotLoaded = true
		}
	}

	validResolvers, resultsErr := readScannerResultFile(resultsPath)
	if resultsErr != nil && snapshotLoaded {
		validResolvers = append([]string(nil), snapshot.State.ValidResolvers...)
	}
	if len(validResolvers) == 0 && snapshotLoaded && len(snapshot.State.ValidResolvers) > 0 {
		validResolvers = append([]string(nil), snapshot.State.ValidResolvers...)
	}
	if !snapshotLoaded && len(validResolvers) == 0 {
		return model.ScannerState{}, "", false
	}

	state := snapshot.State
	if !snapshotLoaded {
		state = model.ScannerState{
			Status:       model.ScannerFailed,
			Mode:         dnsScannerModeManual,
			Phase:        "recovered",
			Message:      fmt.Sprintf("Recovered %d valid resolver%s from the previous DNS scanner run.", len(validResolvers), pluralSuffix(len(validResolvers))),
			ScanParallel: defaultDNSScannerParallel,
			FinishedAt:   time.Now().UnixMilli(),
		}
	}
	if state.Status == "" {
		state.Status = model.ScannerFailed
	}
	if state.Mode == "" {
		state.Mode = dnsScannerModeManual
	}
	if state.ScanParallel <= 0 {
		state.ScanParallel = defaultDNSScannerParallel
	}
	state.ValidResolvers = validResolvers
	if len(validResolvers) > state.Valid {
		state.Valid = len(validResolvers)
	}
	if completed := state.Valid + state.Rejected; completed > state.Completed {
		state.Completed = completed
	}
	if state.Total > 0 && state.Completed > state.Total {
		state.Completed = state.Total
	}
	if state.Status == model.ScannerRunning {
		state.Status = model.ScannerFailed
		state.Paused = false
		state.Phase = "recovered"
		state.Error = "DNS scanner stopped before completion"
		state.Message = fmt.Sprintf("Previous DNS scanner run was interrupted; recovered %d valid resolver%s.", len(validResolvers), pluralSuffix(len(validResolvers)))
		if state.FinishedAt == 0 {
			state.FinishedAt = time.Now().UnixMilli()
		}
	}
	return state, snapshot.InputPath, true
}

func (a *App) appendScannerValidResolverLocked(resolver string) error {
	if strings.TrimSpace(a.scannerResultsPath) == "" {
		return nil
	}
	return appendScannerResultFile(a.scannerResultsPath, resolver)
}

func (a *App) persistScannerSnapshotLocked() {
	if strings.TrimSpace(a.scannerSnapshotPath) == "" {
		return
	}
	snapshot := scannerPersistedSnapshot{
		Version:   1,
		InputPath: a.scannerInputPath,
		State:     cloneScannerState(a.scannerState),
		UpdatedAt: time.Now().UnixMilli(),
	}
	if err := writeScannerSnapshot(a.scannerSnapshotPath, snapshot); err != nil && a.scannerState.Status == model.ScannerRunning {
		a.scannerState.Error = err.Error()
		a.scannerState.Message = "DNS scanner could not save progress"
	}
}

func (a *App) resetScannerResultsFileLocked() {
	if strings.TrimSpace(a.scannerResultsPath) != "" {
		_ = os.Remove(a.scannerResultsPath)
	}
}

func (a *App) clearScannerPersistenceLocked() {
	if strings.TrimSpace(a.scannerSnapshotPath) != "" {
		_ = os.Remove(a.scannerSnapshotPath)
	}
	if strings.TrimSpace(a.scannerResultsPath) != "" {
		_ = os.Remove(a.scannerResultsPath)
	}
}

func writeScannerSnapshot(path string, snapshot scannerPersistedSnapshot) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return writeAtomicScannerFile(path, append(raw, '\n'), 0o600)
}

func appendScannerResultFile(path string, resolver string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(resolver) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(strings.TrimSpace(resolver) + "\n")
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (a *App) refreshScannerValidResolversLocked() error {
	if strings.TrimSpace(a.scannerResultsPath) == "" {
		return nil
	}
	validResolvers, err := readScannerResultFile(a.scannerResultsPath)
	if err != nil {
		return err
	}
	if validResolvers == nil {
		validResolvers = []string{}
	}
	a.scannerState.ValidResolvers = validResolvers
	if len(validResolvers) > a.scannerState.Valid {
		a.scannerState.Valid = len(validResolvers)
	}
	return nil
}

func readScannerResultFile(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := map[string]struct{}{}
	resolvers := make([]string, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		resolver := strings.TrimSpace(scanner.Text())
		if resolver == "" {
			continue
		}
		if _, exists := seen[resolver]; exists {
			continue
		}
		seen[resolver] = struct{}{}
		resolvers = append(resolvers, resolver)
	}
	return resolvers, scanner.Err()
}

func writeAtomicScannerFile(path string, data []byte, perm os.FileMode) error {
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(tmp)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func (a *App) normalizeScannerInputFile(sourcePath string) (scannerInputSummary, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return scannerInputSummary{}, err
	}
	defer source.Close()

	configDir, err := appConfigDir()
	if err != nil {
		return scannerInputSummary{}, err
	}
	destDir := filepath.Join(configDir, dnsScannerInputDirName)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return scannerInputSummary{}, err
	}
	dest := filepath.Join(destDir, fmt.Sprintf("scanner-input-%d.resolvers", time.Now().UnixNano()))
	tmp := fmt.Sprintf("%s.%d.tmp", dest, time.Now().UnixNano())
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return scannerInputSummary{}, err
	}

	summary := scannerInputSummary{
		Path:     dest,
		FileName: filepath.Base(sourcePath),
	}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		for _, token := range scannerInputTokens(scanner.Text()) {
			resolvers, ok := scannerResolversFromToken(token)
			if !ok {
				summary.Invalid++
				continue
			}
			for _, resolver := range resolvers {
				if _, exists := seen[resolver]; exists {
					summary.Duplicates++
					continue
				}
				seen[resolver] = struct{}{}
				if _, err := out.WriteString(resolver + "\n"); err != nil {
					_ = out.Close()
					_ = os.Remove(tmp)
					return summary, err
				}
				summary.Total++
			}
		}
	}
	closeErr := out.Close()
	if err := scanner.Err(); err != nil {
		_ = os.Remove(tmp)
		return summary, err
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return summary, closeErr
	}
	if summary.Total == 0 {
		_ = os.Remove(tmp)
		return summary, fmt.Errorf("scanner input file contains no valid DNS resolver IPs")
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return summary, err
	}
	return summary, nil
}

func scannerInputTokens(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return nil
	}
	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		token := strings.Trim(strings.TrimSpace(part), `"'`)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func scannerResolversFromToken(token string) ([]string, bool) {
	target, ok := scannerTargetWithoutPort(token)
	if !ok {
		return nil, false
	}
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil {
			return nil, false
		}
		return expandScannerPrefix(prefix)
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return nil, false
	}
	return []string{addr.Unmap().String()}, true
}

func scannerTargetWithoutPort(token string) (string, bool) {
	text := strings.Trim(strings.TrimSpace(token), `"'`)
	if text == "" {
		return "", false
	}
	if strings.HasPrefix(text, "[") {
		end := strings.Index(text, "]")
		if end <= 1 {
			return "", false
		}
		host := strings.TrimSpace(text[1:end])
		remainder := strings.TrimSpace(text[end+1:])
		if remainder == "" {
			return host, true
		}
		if strings.HasPrefix(remainder, ":") && scannerPortIsValid(strings.TrimSpace(remainder[1:])) {
			return host, true
		}
		return "", false
	}
	if addrPort, err := netip.ParseAddrPort(text); err == nil {
		return addrPort.Addr().Unmap().String(), true
	}
	if host, port, ok := strings.Cut(text, ":"); ok && !strings.Contains(host, ":") && scannerPortIsValid(port) {
		return strings.TrimSpace(host), true
	}
	if idx := strings.LastIndex(text, ":"); idx > 0 && strings.Contains(text[:idx], "/") && scannerPortIsValid(text[idx+1:]) {
		return strings.TrimSpace(text[:idx]), true
	}
	return text, true
}

func scannerPortIsValid(raw string) bool {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	return err == nil && port >= 1 && port <= 65535
}

func expandScannerPrefix(prefix netip.Prefix) ([]string, bool) {
	prefix = prefix.Masked()
	count, ok := scannerUsableHostCount(prefix)
	if !ok || count <= 0 || count > maxDNSScannerRangeHosts {
		return nil, false
	}
	first, last := scannerHostRange(prefix)
	if !first.IsValid() || !last.IsValid() {
		return nil, false
	}
	out := make([]string, 0, count)
	for addr := first; ; addr = addr.Next() {
		out = append(out, addr.Unmap().String())
		if addr == last {
			break
		}
	}
	return out, true
}

func scannerUsableHostCount(prefix netip.Prefix) (int, bool) {
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if addr.Is4() {
		hostBits := 32 - prefix.Bits()
		switch {
		case hostBits == 0:
			return 1, true
		case hostBits == 1:
			return 2, true
		case hostBits > 31:
			return 0, false
		default:
			return (1 << hostBits) - 2, true
		}
	}
	hostBits := 128 - prefix.Bits()
	if hostBits > 16 {
		return 0, false
	}
	total := 1 << hostBits
	if prefix.Bits() < 127 {
		return total - 1, true
	}
	return total, true
}

func scannerHostRange(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	network := prefix.Addr().Unmap()
	last := scannerPrefixLastAddr(prefix)
	if network.Is4() && prefix.Bits() < 31 {
		return network.Next(), scannerPrevAddr(last)
	}
	if network.Is6() && prefix.Bits() < 127 {
		return network.Next(), last
	}
	return network, last
}

func scannerPrefixLastAddr(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		b := addr.As4()
		hostBits := 32 - prefix.Bits()
		value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if hostBits > 0 {
			value |= (uint32(1) << hostBits) - 1
		}
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	b := addr.As16()
	hostBits := 128 - prefix.Bits()
	for bit := 0; bit < hostBits; bit++ {
		idx := 15 - bit/8
		b[idx] |= 1 << (bit % 8)
	}
	return netip.AddrFrom16(b)
}

func scannerPrevAddr(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}
	if addr.Is4() {
		b := addr.As4()
		value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if value == 0 {
			return addr
		}
		value--
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	b := addr.As16()
	for idx := 15; idx >= 0; idx-- {
		if b[idx] > 0 {
			b[idx]--
			break
		}
		b[idx] = 0xff
	}
	return netip.AddrFrom16(b)
}

func (a *App) scannerConnection(id string) (model.ConnectionProfile, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := profiles.NormalizeStatePreservingRuntime(a.state)
	id = strings.TrimSpace(id)
	if id == "" {
		id = state.SelectedConnectionProfileID
	}
	for _, profile := range state.ConnectionProfiles {
		if profile.ID != id {
			continue
		}
		if strings.TrimSpace(profile.Domain) == "" {
			return model.ConnectionProfile{}, fmt.Errorf("connection profile needs a MasterDNS/StormDNS domain")
		}
		if strings.TrimSpace(profile.EncryptionKey) == "" {
			return model.ConnectionProfile{}, fmt.Errorf("connection profile needs an encryption key")
		}
		if model.NormalizeImportType(profile.ImportType) != model.ImportTypeMasterDNS {
			return model.ConnectionProfile{}, fmt.Errorf("DNS scanner requires a MasterDNS connection profile")
		}
		return profile, nil
	}
	return model.ConnectionProfile{}, fmt.Errorf("connection profile not found")
}

func (a *App) scannerBootstrapResolverFile(connectionID string, runtimeDir string) (string, error) {
	a.mu.Lock()
	state := profiles.NormalizeStatePreservingRuntime(a.state)
	a.mu.Unlock()
	profile, ok := scannerResolverProfileForConnection(state, connectionID)
	if !ok {
		return "", fmt.Errorf("resolver profile is missing")
	}
	if strings.EqualFold(strings.TrimSpace(profile.ResolverSource), "file") {
		path := strings.TrimSpace(profile.ResolverFile)
		if path == "" {
			return "", fmt.Errorf("resolver file is missing")
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", fmt.Errorf("resolver file is unavailable")
		}
		if profile.ResolverCount <= 0 {
			return "", fmt.Errorf("at least one bootstrap resolver is required")
		}
		return path, nil
	}

	validation := resolver.ValidateText(profile.ResolverText)
	if !validation.IsValid {
		if len(validation.InvalidEntries) > 0 {
			return "", fmt.Errorf("resolver list contains invalid entries")
		}
		return "", fmt.Errorf("at least one bootstrap resolver is required")
	}
	path := filepath.Join(runtimeDir, "bootstrap-resolvers.txt")
	if err := os.WriteFile(path, []byte(validation.NormalizedText+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (a *App) connectionUpgradeScanPlan(state model.AppState, settings model.SettingsProfile) (connectionUpgradeScanPlan, error) {
	connection, ok := storm.SelectedConnection(state)
	if !ok {
		return connectionUpgradeScanPlan{}, fmt.Errorf("connection profile is missing")
	}
	resolverProfile, ok := scannerResolverProfileForConnection(state, connection.ID)
	if !ok {
		return connectionUpgradeScanPlan{}, fmt.Errorf("resolver profile is missing")
	}
	profileResolvers, err := resolverProfileResolvers(resolverProfile)
	if err != nil {
		return connectionUpgradeScanPlan{}, err
	}
	if len(profileResolvers) == 0 {
		return connectionUpgradeScanPlan{}, fmt.Errorf("at least one bootstrap resolver is required")
	}

	settings = profiles.NormalizeSettingsProfile(settings)
	bootstrapCount := settings.UploadDuplication
	if bootstrapCount < 1 {
		bootstrapCount = 1
	}
	if bootstrapCount > len(profileResolvers) {
		bootstrapCount = len(profileResolvers)
	}

	plan := connectionUpgradeScanPlan{
		Connection:         connection,
		Settings:           settings,
		BootstrapResolvers: append([]string(nil), profileResolvers[:bootstrapCount]...),
		CandidateResolvers: append([]string(nil), profileResolvers...),
		CandidateTotal:     len(profileResolvers),
		ScanParallel:       settings.MTUTestParallelismResolvers,
		AutoRestart:        false,
	}
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		a.scannerMu.Unlock()
		return connectionUpgradeScanPlan{}, fmt.Errorf("DNS scanner is already running")
	}
	if a.scannerState.ScanParallel > 0 {
		plan.ScanParallel = a.scannerState.ScanParallel
	}
	if strings.TrimSpace(a.scannerInputPath) != "" && a.scannerState.Total > 0 {
		plan.CandidateInputPath = a.scannerInputPath
		plan.CandidateInputFileName = a.scannerState.InputFileName
		plan.CandidateTotal = a.scannerState.Total
		plan.CandidateInvalid = a.scannerState.Invalid
		plan.CandidateDuplicates = a.scannerState.Duplicates
		plan.CandidateResolvers = nil
	}
	a.scannerMu.Unlock()
	if strings.TrimSpace(plan.CandidateInputFileName) == "" {
		plan.CandidateInputFileName = resolverProfile.Name
	}
	plan.ScanParallel = normalizeDNSScannerParallel(plan.ScanParallel)
	return plan, nil
}

func resolverProfileResolvers(profile model.ResolverProfile) ([]string, error) {
	if strings.EqualFold(strings.TrimSpace(profile.ResolverSource), "file") {
		path := strings.TrimSpace(profile.ResolverFile)
		if path == "" {
			return nil, fmt.Errorf("resolver file is missing")
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return nil, fmt.Errorf("resolver file is unavailable")
		}
		resolvers, err := readScannerResultFile(path)
		if err != nil {
			return nil, err
		}
		if len(resolvers) == 0 {
			return nil, fmt.Errorf("at least one resolver is required")
		}
		return resolvers, nil
	}

	validation := resolver.ValidateText(profile.ResolverText)
	if !validation.IsValid {
		if len(validation.InvalidEntries) > 0 {
			return nil, fmt.Errorf("resolver list contains invalid entries")
		}
		return nil, fmt.Errorf("at least one resolver is required")
	}
	return append([]string(nil), validation.NormalizedResolvers...), nil
}

func scannerResolverProfileForConnection(state model.AppState, connectionID string) (model.ResolverProfile, bool) {
	resolverID := strings.TrimSpace(state.SelectedResolverProfileID)
	for _, connection := range state.ConnectionProfiles {
		if connection.ID != connectionID {
			continue
		}
		if strings.TrimSpace(connection.ResolverProfileID) != "" {
			resolverID = strings.TrimSpace(connection.ResolverProfileID)
		}
		break
	}
	for _, profile := range state.ResolverProfiles {
		if profile.ID == resolverID {
			return profile, true
		}
	}
	return model.ResolverProfile{}, false
}

func (a *App) selectedConnectionProfileID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.SelectedConnectionProfileID
}

func normalizeDNSScannerParallel(value int) int {
	if value <= 0 {
		return defaultDNSScannerParallel
	}
	if value > maxDNSScannerParallel {
		return maxDNSScannerParallel
	}
	return value
}

func dnsScannerCommandArgs(configFile string, resolversFile string) []string {
	return []string{"-config", configFile, "-resolvers", resolversFile}
}

func dnsScannerResolverStateComplete(state model.ResolverRuntimeState) bool {
	if state.TotalCount <= 0 || state.PendingCount != 0 {
		return false
	}
	return state.ValidCount+state.RejectedCount == state.TotalCount
}

func dnsScannerResolverStateBelongsToInputScan(state model.ResolverRuntimeState, expectedTotal int) bool {
	if state.TotalCount <= 0 {
		return false
	}
	if expectedTotal > 0 && state.TotalCount != expectedTotal {
		return false
	}
	return true
}

func dnsScannerProgressBelongsToInputScan(progress model.ConnectionProgress, expectedTotal int) bool {
	if progress.Phase != "mtu" || progress.Total <= 0 {
		return false
	}
	if expectedTotal > 0 && progress.Total != expectedTotal {
		return false
	}
	return true
}

func dnsScannerConnectingMessage(mode string) string {
	if mode == dnsScannerModeUpgrade {
		return "Preparing background resolver scanner while the VPN stays connected"
	}
	return "Connecting DNS scanner VPN before scanning input file"
}

func dnsScannerProgressMessage(state model.ScannerState) string {
	if state.Mode == dnsScannerModeUpgrade {
		return connectionUpgradeScannerMessage
	}
	return fmt.Sprintf("Scanning DNS resolvers: %d of %d complete", state.Completed, state.Total)
}

func (a *App) finalizeScannerCompletedCountsLocked() {
	if len(a.scannerState.ValidResolvers) > a.scannerState.Valid {
		a.scannerState.Valid = len(a.scannerState.ValidResolvers)
	}
	if a.scannerState.Total <= 0 {
		return
	}
	if a.scannerState.Completed < a.scannerState.Total {
		a.scannerState.Completed = a.scannerState.Total
	}
	rejected := a.scannerState.Total - a.scannerState.Valid
	if rejected < 0 {
		rejected = 0
	}
	if a.scannerState.Rejected < rejected {
		a.scannerState.Rejected = rejected
	}
}

func (a *App) applyScannerCompletionMessageLocked() {
	if a.scannerState.Mode != dnsScannerModeUpgrade {
		a.scannerState.Message = fmt.Sprintf("DNS scanner completed: %d valid, %d rejected", a.scannerState.Valid, a.scannerState.Rejected)
		return
	}
	a.scannerState.AutoRestart = false
	a.scannerState.RestartAvailable = a.scannerState.Valid > 0 || len(a.scannerState.ValidResolvers) > 0
	if a.scannerState.RestartAvailable {
		a.scannerState.Message = fmt.Sprintf("Background scan completed: %d best resolver%s found. Choose whether to restart the VPN with these resolvers.", a.scannerState.Valid, pluralSuffix(a.scannerState.Valid))
		return
	}
	a.scannerState.Message = "Background scan completed with no valid resolvers. The VPN is still using the current session."
}

func scannerRandomPorts() (int, int, error) {
	listenPort, err := freeLocalTCPPort()
	if err != nil {
		return 0, 0, err
	}
	apiPort, err := freeLocalTCPPort()
	if err != nil {
		return 0, 0, err
	}
	for apiPort == listenPort {
		apiPort, err = freeLocalTCPPort()
		if err != nil {
			return 0, 0, err
		}
	}
	return listenPort, apiPort, nil
}

func newDNSScannerRuntimeDir() (string, error) {
	runtimeRoot := ""
	if configDir, err := appConfigDir(); err == nil {
		runtimeRoot = filepath.Join(configDir, "runtime", dnsScannerRuntimeDirName)
	}
	if runtimeRoot == "" {
		runtimeRoot = filepath.Join(os.TempDir(), "whitevpn-desktop", dnsScannerRuntimeDirName)
	}
	if err := os.MkdirAll(runtimeRoot, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(runtimeRoot, "scan-")
}

func cloneScannerState(state model.ScannerState) model.ScannerState {
	state.ValidResolvers = append([]string(nil), state.ValidResolvers...)
	return state
}

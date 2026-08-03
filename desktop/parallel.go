package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	runtimemgr "whitevpn-desktop/internal/runtime"
	"whitevpn-desktop/internal/storm"

	"golang.org/x/net/proxy"
)

const (
	parallelCandidateBatchSize  = 3
	parallelSpeedCandidateCount = 3
	parallelSpeedTestTimeout    = 5 * time.Second
	parallelSpeedTestMaxBytes   = 2 * 1024 * 1024
	parallelRuntimeDirName      = "parallel-test"
	parallelResolverProfileID   = "parallel-test-minimum-resolvers"
	parallelCandidatePending    = "pending"
	parallelCandidateRunning    = "running"
	parallelCandidateConnected  = "connected"
	parallelCandidateFailed     = "failed"
	parallelCandidateCancelled  = "cancelled"
	parallelPhaseResolvers      = "resolvers"
	parallelPhaseCandidates     = "candidates"
	parallelPhaseConnecting     = "connecting"
)

type parallelRuntimeManager interface {
	Start(context.Context, storm.LaunchConfig) error
	StartXray(context.Context, runtimemgr.XrayLaunchConfig) error
	Stop() error
}

type parallelTestPreset struct {
	ID       string
	Name     string
	Category string
	Settings model.SettingsProfile
}

type parallelCandidateRunner func(context.Context, model.AppState, parallelTestPreset, []string) model.ParallelTestCandidateResult

type parallelResolverUpdate struct {
	presetID    string
	state       model.ResolverRuntimeState
	progress    model.ConnectionProgress
	hasProgress bool
	err         error
}

type parallelSpeedTestResult struct {
	bytesPerSecond int64
	bytes          int64
	duration       time.Duration
	err            error
}

var parallelSpeedTestURLs = []string{
	"https://speed.cloudflare.com/__down?bytes=2097152",
	"https://proof.ovh.net/files/1Mb.dat",
}

func (a *App) GetParallelTestState() model.ParallelTestState {
	a.parallelMu.Lock()
	defer a.parallelMu.Unlock()
	if a.parallelState.Status == "" {
		a.parallelState = model.DefaultParallelTestState()
	}
	return cloneParallelTestState(a.parallelState)
}

func (a *App) GetParallelTestPresetOptions() []model.ParallelTestPresetOption {
	a.mu.Lock()
	state := profiles.NormalizeState(a.state)
	a.mu.Unlock()
	return parallelTestPresetOptions(state, nil)
}

func (a *App) SaveParallelTestPresets(presetIDs []string) (model.AppState, error) {
	a.mu.Lock()
	state := profiles.NormalizeStatePreservingRuntime(a.state)
	options := parallelTestPresetOptions(state, presetIDs)
	if len(options) == 0 {
		a.mu.Unlock()
		return state, fmt.Errorf("no auto-tune presets selected")
	}
	existingNames := settingsProfileNames(state.SettingsProfiles)
	for _, option := range options {
		nameKey := settingsProfileNameKey(option.Name)
		if _, exists := existingNames[nameKey]; exists {
			continue
		}
		profile := profiles.NormalizeSettingsProfile(option.Settings)
		profile.ID = uniqueSettingsProfileID(state.SettingsProfiles, "settings-autotune-"+option.ID)
		profile.Name = option.Name
		state.SettingsProfiles = append(state.SettingsProfiles, profile)
		existingNames[nameKey] = struct{}{}
	}
	a.state = state
	next, err := a.saveLocked()
	a.mu.Unlock()
	if err == nil {
		a.emit("app:state", next)
	}
	return next, err
}

func (a *App) StartParallelTest(presetIDs []string) (model.ParallelTestState, error) {
	a.parallelMu.Lock()
	if a.parallelState.Status == model.ParallelTestRunning {
		state := cloneParallelTestState(a.parallelState)
		a.parallelMu.Unlock()
		return state, fmt.Errorf("parallel test is already running")
	}
	a.parallelMu.Unlock()

	a.mu.Lock()
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.Status != model.RuntimeFailed {
		a.mu.Unlock()
		return a.GetParallelTestState(), fmt.Errorf("stop the active connection before parallel testing")
	}
	baseState := profiles.NormalizeState(a.state)
	if _, err := storm.BuildLaunchConfig(baseState); err != nil {
		a.mu.Unlock()
		return a.GetParallelTestState(), err
	}
	a.mu.Unlock()

	presets := parallelTestPresetsFromSelection(baseState, presetIDs)
	if len(presets) == 0 {
		return a.GetParallelTestState(), fmt.Errorf("no parallel test configs selected")
	}
	resolverTarget := parallelResolverTargetForState(baseState)
	candidates := make([]model.ParallelTestCandidateResult, 0, len(presets))
	for _, preset := range presets {
		candidates = append(candidates, model.ParallelTestCandidateResult{
			ID:     preset.ID,
			Name:   preset.Name,
			Status: parallelCandidatePending,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UnixMilli()
	a.parallelMu.Lock()
	a.parallelRunID++
	runID := a.parallelRunID
	a.parallelCancel = cancel
	a.parallelState = model.ParallelTestState{
		Status:         model.ParallelTestRunning,
		Phase:          parallelPhaseResolvers,
		Message:        fmt.Sprintf("Finding up to %d valid resolvers", resolverTarget),
		ResolverTarget: resolverTarget,
		Total:          resolverTarget,
		Error:          "",
		StartedAt:      now,
		Resolvers:      []string{},
		Candidates:     candidates,
	}
	state := cloneParallelTestState(a.parallelState)
	a.parallelMu.Unlock()
	a.emit("parallel-test:state", state)

	go a.runParallelTest(ctx, runID, baseState, presets)
	return state, nil
}

func (a *App) CancelParallelTest() (model.ParallelTestState, error) {
	var cancel context.CancelFunc
	a.parallelMu.Lock()
	if a.parallelState.Status != model.ParallelTestRunning {
		state := cloneParallelTestState(a.parallelState)
		a.parallelMu.Unlock()
		return state, nil
	}
	cancel = a.parallelCancel
	a.parallelCancel = nil
	a.parallelState.Status = model.ParallelTestCancelled
	a.parallelState.Message = "Parallel test cancelled"
	a.parallelState.FinishedAt = time.Now().UnixMilli()
	state := cloneParallelTestState(a.parallelState)
	a.parallelMu.Unlock()

	if cancel != nil {
		cancel()
	}
	a.emit("parallel-test:state", state)
	return state, nil
}

func (a *App) parallelTestRunning() bool {
	a.parallelMu.Lock()
	defer a.parallelMu.Unlock()
	return a.parallelState.Status == model.ParallelTestRunning
}

func (a *App) clearFinishedParallelTest() {
	a.parallelMu.Lock()
	if a.parallelState.Status == "" {
		a.parallelState = model.DefaultParallelTestState()
	}
	if a.parallelState.Status == model.ParallelTestIdle || a.parallelState.Status == model.ParallelTestRunning {
		a.parallelMu.Unlock()
		return
	}
	a.parallelCancel = nil
	a.parallelState = model.DefaultParallelTestState()
	state := cloneParallelTestState(a.parallelState)
	a.parallelMu.Unlock()
	a.emit("parallel-test:state", state)
}

func (a *App) runParallelTest(ctx context.Context, runID int64, baseState model.AppState, presets []parallelTestPreset) {
	resolverTarget := parallelResolverTargetForState(baseState)
	resolvers, err := a.findParallelTestResolvers(ctx, runID, baseState, resolverTarget)
	if err != nil {
		a.finishParallelTest(runID, model.ParallelTestFailed, parallelPhaseResolvers, err.Error())
		return
	}
	if ctx.Err() != nil {
		a.finishParallelTest(runID, model.ParallelTestCancelled, parallelPhaseResolvers, "Parallel test cancelled")
		return
	}

	a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
		state.Phase = parallelPhaseCandidates
		state.Message = "Quick testing selected configs"
		state.Total = len(presets)
		state.Completed = 0
		state.Running = 0
		state.Resolvers = append([]string(nil), resolvers...)
	})

	results := runParallelTestCandidates(
		ctx,
		baseState,
		presets,
		resolvers,
		parallelCandidateBatchSize,
		a.runParallelCandidateStartup,
		func(result model.ParallelTestCandidateResult) {
			a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
				updateParallelCandidate(state, result)
				state.Completed = countParallelCandidates(state.Candidates, func(candidate model.ParallelTestCandidateResult) bool {
					return candidate.Status == parallelCandidateConnected || candidate.Status == parallelCandidateFailed || candidate.Status == parallelCandidateCancelled
				})
				state.Running = countParallelCandidates(state.Candidates, func(candidate model.ParallelTestCandidateResult) bool {
					return candidate.Status == parallelCandidateRunning
				})
			})
		},
	)

	if ctx.Err() != nil {
		a.finishParallelTest(runID, model.ParallelTestCancelled, parallelPhaseCandidates, "Parallel test cancelled")
		return
	}

	speedCandidates := topParallelCandidates(results, parallelSpeedCandidateCount)
	speedPresets := presetsFromCandidateResults(presets, speedCandidates)
	if len(speedPresets) > 0 {
		speedIDs := map[string]struct{}{}
		for _, preset := range speedPresets {
			speedIDs[preset.ID] = struct{}{}
		}
		a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
			state.Message = fmt.Sprintf("Speed testing top %d configs", len(speedPresets))
			state.Total = len(presets) + len(speedPresets)
			state.Completed = len(presets)
			state.Running = 0
		})
		speedResults := runParallelTestCandidates(
			ctx,
			baseState,
			speedPresets,
			resolvers,
			parallelCandidateBatchSize,
			a.runParallelCandidateSpeed,
			func(result model.ParallelTestCandidateResult) {
				a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
					updateParallelCandidate(state, result)
					state.Completed = len(presets) + countParallelCandidates(state.Candidates, func(candidate model.ParallelTestCandidateResult) bool {
						_, ok := speedIDs[candidate.ID]
						return ok && (candidate.Status == parallelCandidateConnected || candidate.Status == parallelCandidateFailed || candidate.Status == parallelCandidateCancelled)
					})
					state.Running = countParallelCandidates(state.Candidates, func(candidate model.ParallelTestCandidateResult) bool {
						return candidate.Status == parallelCandidateRunning
					})
				})
			},
		)
		for _, result := range speedResults {
			replaceParallelCandidate(results, result)
		}
	}

	if ctx.Err() != nil {
		a.finishParallelTest(runID, model.ParallelTestCancelled, parallelPhaseCandidates, "Parallel test cancelled")
		return
	}

	winner, ok := bestParallelCandidate(results)
	if !ok {
		a.finishParallelTest(runID, model.ParallelTestFailed, parallelPhaseCandidates, "No auto-tune config connected successfully")
		return
	}
	winnerPreset, ok := presetByID(presets, winner.ID)
	if !ok {
		a.finishParallelTest(runID, model.ParallelTestFailed, parallelPhaseCandidates, "Winning preset is unavailable")
		return
	}

	a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
		state.Phase = parallelPhaseConnecting
		state.Message = fmt.Sprintf("Connecting with %s", winnerPreset.Name)
		state.WinnerPresetID = winnerPreset.ID
		state.WinnerPresetName = winnerPreset.Name
	})

	winnerSettings, savedWinner, err := a.selectParallelWinnerPreset(winnerPreset)
	if err != nil {
		a.finishParallelTest(runID, model.ParallelTestFailed, parallelPhaseConnecting, err.Error())
		return
	}
	if ctx.Err() != nil {
		a.finishParallelTest(runID, model.ParallelTestCancelled, parallelPhaseConnecting, "Parallel test cancelled")
		return
	}
	var connectErr error
	if savedWinner {
		_, connectErr = a.startConnectionWithSettings(ctx, nil, winnerPreset.ID, winnerPreset.Name, resolvers)
	} else {
		_, connectErr = a.startConnectionWithSettings(ctx, &winnerSettings, winnerPreset.ID, winnerPreset.Name, resolvers)
	}
	if connectErr != nil {
		if errors.Is(connectErr, context.Canceled) {
			a.finishParallelTest(runID, model.ParallelTestCancelled, parallelPhaseConnecting, "Parallel test cancelled")
			return
		}
		a.finishParallelTest(runID, model.ParallelTestFailed, parallelPhaseConnecting, connectErr.Error())
		return
	}
	a.finishParallelTest(runID, model.ParallelTestCompleted, parallelPhaseConnecting, fmt.Sprintf("Connected with %s", winnerPreset.Name))
}

type autoTunePresetDefinition struct {
	ID                  string
	Name                string
	Category            string
	UploadMin           int
	UploadMax           int
	DownloadMin         int
	DownloadMax         int
	Timeout             float64
	Fragments           int
	UploadDuplication   int
	DownloadDuplication int
	UploadCompression   int
	DownloadCompression int
}

func parallelTestPresetOptions(state model.AppState, presetIDs []string) []model.ParallelTestPresetOption {
	base, ok := storm.SelectedSettings(state)
	if !ok {
		base = model.DefaultSettingsProfile()
	}
	base = profiles.NormalizeSettingsProfile(base)
	selectedIDs := map[string]struct{}{}
	for _, id := range presetIDs {
		source, id := parallelSelectionParts(id)
		if source == "settings" {
			continue
		}
		if id != "" {
			selectedIDs[id] = struct{}{}
		}
	}
	savedByName := settingsProfilesByName(state.SettingsProfiles)
	definitions := autoTuneParallelPresetDefinitions()
	options := make([]model.ParallelTestPresetOption, 0, len(definitions))
	for _, definition := range definitions {
		if len(selectedIDs) > 0 {
			if _, selected := selectedIDs[definition.ID]; !selected {
				continue
			}
		}
		settings := settingsProfileFromAutoTuneDefinition(base, definition)
		saved := false
		if existing, ok := savedByName[settingsProfileNameKey(definition.Name)]; ok {
			settings = profiles.NormalizeSettingsProfile(existing)
			saved = true
		}
		options = append(options, model.ParallelTestPresetOption{
			ID:       definition.ID,
			Name:     definition.Name,
			Category: definition.Category,
			Saved:    saved,
			Settings: settings,
		})
	}
	return options
}

func parallelTestPresetsFromSelection(state model.AppState, selectionIDs []string) []parallelTestPreset {
	trimmed := make([]string, 0, len(selectionIDs))
	for _, id := range selectionIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			trimmed = append(trimmed, id)
		}
	}
	if len(trimmed) == 0 {
		return parallelTestPresetsFromOptions(parallelTestPresetOptions(state, nil))
	}

	settingsByID := map[string]model.SettingsProfile{}
	for _, profile := range state.SettingsProfiles {
		settingsByID[profile.ID] = profiles.NormalizeSettingsProfile(profile)
	}
	seen := map[string]struct{}{}
	presets := make([]parallelTestPreset, 0, len(trimmed))
	for _, rawID := range trimmed {
		source, id := parallelSelectionParts(rawID)
		var preset parallelTestPreset
		var ok bool
		switch source {
		case "settings":
			if profile, exists := settingsByID[id]; exists {
				preset = parallelTestPreset{
					ID:       "settings:" + profile.ID,
					Name:     profile.Name,
					Category: "Your settings",
					Settings: profile,
				}
				ok = true
			}
		default:
			options := parallelTestPresetOptions(state, []string{id})
			if len(options) > 0 {
				preset = parallelTestPresetsFromOptions(options)[0]
				ok = true
			}
		}
		if !ok {
			continue
		}
		if _, exists := seen[preset.ID]; exists {
			continue
		}
		seen[preset.ID] = struct{}{}
		presets = append(presets, preset)
	}
	return presets
}

func parallelTestPresetsFromOptions(options []model.ParallelTestPresetOption) []parallelTestPreset {
	presets := make([]parallelTestPreset, 0, len(options))
	for _, option := range options {
		presets = append(presets, parallelTestPreset{
			ID:       option.ID,
			Name:     option.Name,
			Category: option.Category,
			Settings: profiles.NormalizeSettingsProfile(option.Settings),
		})
	}
	return presets
}

func parallelSelectionParts(rawID string) (string, string) {
	rawID = strings.TrimSpace(rawID)
	if rawID == "" {
		return "builtin", ""
	}
	source, id, ok := strings.Cut(rawID, ":")
	if !ok {
		return "builtin", rawID
	}
	source = strings.TrimSpace(strings.ToLower(source))
	id = strings.TrimSpace(id)
	switch source {
	case "settings", "builtin":
		return source, id
	default:
		return "builtin", rawID
	}
}

func autoTuneParallelPresetDefinitions() []autoTunePresetDefinition {
	return []autoTunePresetDefinition{
		{ID: "iran-default", Name: "Iran Default", Category: "Stable", UploadMin: 40, UploadMax: 140, DownloadMin: 300, DownloadMax: 3000, Timeout: 2.5, Fragments: 256, UploadDuplication: 3, DownloadDuplication: 7, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-low-mtu-scan", Name: "Iran Low MTU Scan", Category: "Stable", UploadMin: 20, UploadMax: 120, DownloadMin: 160, DownloadMax: 768, Timeout: 2.5, Fragments: 256, UploadDuplication: 3, DownloadDuplication: 7, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-fast-low-mtu", Name: "Iran Fast Low MTU", Category: "Stable", UploadMin: 20, UploadMax: 325, DownloadMin: 100, DownloadMax: 1270, Timeout: 2.5, Fragments: 100, UploadDuplication: 5, DownloadDuplication: 10, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-compact-fixed", Name: "Iran Compact Fixed", Category: "Stable", UploadMin: 62, UploadMax: 62, DownloadMin: 414, DownloadMax: 414, Timeout: 2.5, Fragments: 384, UploadDuplication: 6, DownloadDuplication: 8, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-fixed-64-balanced", Name: "Iran Fixed 64 Balanced", Category: "Stable", UploadMin: 64, UploadMax: 64, DownloadMin: 756, DownloadMax: 756, Timeout: 2.5, Fragments: 256, UploadDuplication: 8, DownloadDuplication: 8, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-mid-reliable", Name: "Iran Mid Reliable", Category: "Stable", UploadMin: 120, UploadMax: 160, DownloadMin: 652, DownloadMax: 1110, Timeout: 2.5, Fragments: 256, UploadDuplication: 5, DownloadDuplication: 11, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-download-heavy", Name: "Iran Download Heavy", Category: "Stable", UploadMin: 104, UploadMax: 139, DownloadMin: 394, DownloadMax: 1000, Timeout: 2.5, Fragments: 256, UploadDuplication: 8, DownloadDuplication: 30, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-fixed-64-wide", Name: "Iran Fixed 64 Wide", Category: "Aggressive", UploadMin: 64, UploadMax: 64, DownloadMin: 756, DownloadMax: 1317, Timeout: 2.5, Fragments: 230, UploadDuplication: 14, DownloadDuplication: 30, UploadCompression: 2, DownloadCompression: 2},
		{ID: "iran-no-compression-max", Name: "Iran No Compression Max", Category: "Aggressive", UploadMin: 100, UploadMax: 600, DownloadMin: 800, DownloadMax: 6500, Timeout: 2.5, Fragments: 640, UploadDuplication: 23, DownloadDuplication: 30, UploadCompression: 0, DownloadCompression: 0},
		{ID: "iran-wide-range-max", Name: "Iran Wide Range Max", Category: "Aggressive", UploadMin: 100, UploadMax: 1000, DownloadMin: 200, DownloadMax: 2667, Timeout: 2.5, Fragments: 256, UploadDuplication: 15, DownloadDuplication: 30, UploadCompression: 2, DownloadCompression: 2},
	}
}

func settingsProfileFromAutoTuneDefinition(base model.SettingsProfile, definition autoTunePresetDefinition) model.SettingsProfile {
	settings := base
	settings.ID = "settings-autotune-" + definition.ID
	settings.Name = definition.Name
	settings.StartupMode = "resolvers"
	settings.MinUploadMTU = definition.UploadMin
	settings.MaxUploadMTU = definition.UploadMax
	settings.MinDownloadMTU = definition.DownloadMin
	settings.MaxDownloadMTU = definition.DownloadMax
	settings.MTUTestTimeoutResolvers = definition.Timeout
	settings.MTUTestTimeoutLogs = definition.Timeout
	settings.DNSResponseFragmentStoreCapacity = definition.Fragments
	settings.UploadDuplication = definition.UploadDuplication
	settings.DownloadDuplication = definition.DownloadDuplication
	settings.UploadCompression = definition.UploadCompression
	settings.DownloadCompression = definition.DownloadCompression
	return profiles.NormalizeSettingsProfile(settings)
}

func (a *App) findParallelTestResolvers(ctx context.Context, runID int64, baseState model.AppState, target int) ([]string, error) {
	discoveryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	preset := parallelResolverDiscoveryPreset(baseState)
	updates := make(chan parallelResolverUpdate, 16)
	done := make(chan error, 1)
	go func() {
		err := a.runParallelDiscoveryCandidate(discoveryCtx, runID, baseState, preset, updates)
		done <- err
	}()

	var latest []string
	var latestProgress model.ConnectionProgress
	var latestResolverState model.ResolverRuntimeState
	for {
		select {
		case update := <-updates:
			if update.err != nil {
				if len(latest) > 0 {
					return latest, nil
				}
				return nil, fmt.Errorf("could not find any valid resolvers: %v", update.err)
			}
			if update.hasProgress {
				latestProgress = update.progress
			} else {
				latestResolverState = update.state
				resolvers := resolverCandidatesFromState(update.state)
				if len(resolvers) > len(latest) {
					latest = append([]string(nil), resolvers...)
				}
			}
			a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
				state.Completed = min(len(latest), target)
				state.Running = 1
				state.Resolvers = append([]string(nil), latest...)
				if len(latest) > 0 {
					state.Message = fmt.Sprintf("Found %d of %d preferred valid resolvers", min(len(latest), target), target)
				}
			})
			if len(latest) >= target || (len(latest) > 0 && resolverDiscoveryComplete(latestResolverState, latestProgress)) {
				cancel()
				_ = <-done
				return capResolvers(latest, target), nil
			}
		case err := <-done:
			if len(latest) >= target {
				return latest[:target], nil
			}
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(ctx.Err(), context.Canceled) {
				if len(latest) > 0 {
					return latest, nil
				}
				return nil, fmt.Errorf("could not find any valid resolvers: %v", err)
			}
			if len(latest) > 0 {
				return latest, nil
			}
			return nil, fmt.Errorf("could not find any valid resolvers")
		case <-discoveryCtx.Done():
			_ = <-done
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			if len(latest) >= target {
				return latest[:target], nil
			}
			if len(latest) > 0 {
				return latest, nil
			}
			return nil, discoveryCtx.Err()
		}
	}
}

func resolverDiscoveryComplete(state model.ResolverRuntimeState, progress model.ConnectionProgress) bool {
	if progress.Total > 0 && progress.Completed >= progress.Total {
		return true
	}
	if state.TotalCount > 0 && state.PendingCount <= 0 {
		known := maxInt(state.ValidCount+state.RejectedCount, len(state.ValidResolvers))
		if known >= state.TotalCount {
			return true
		}
	}
	return state.ValidComplete && state.PendingCount <= 0 && (state.ValidCount > 0 || len(state.ValidResolvers) > 0)
}

func capResolvers(resolvers []string, target int) []string {
	if target > 0 && len(resolvers) > target {
		return resolvers[:target]
	}
	return resolvers
}

func parallelResolverDiscoveryPreset(state model.AppState) parallelTestPreset {
	settings, ok := storm.SelectedSettings(state)
	if !ok {
		settings = model.DefaultSettingsProfile()
	}
	return parallelTestPreset{
		ID:       "resolver-discovery",
		Name:     "Resolver discovery",
		Category: "Discovery",
		Settings: profiles.NormalizeSettingsProfile(settings),
	}
}

func parallelResolverTargetForState(state model.AppState) int {
	settings, ok := storm.SelectedSettings(state)
	if !ok {
		settings = model.DefaultSettingsProfile()
	}
	settings = profiles.NormalizeSettingsProfile(settings)
	if settings.UploadDuplication <= 0 {
		return 1
	}
	return settings.UploadDuplication
}

func (a *App) runParallelDiscoveryCandidate(ctx context.Context, runID int64, baseState model.AppState, preset parallelTestPreset, updates chan<- parallelResolverUpdate) error {
	var mu sync.Mutex
	var lastRuntimeError string
	manager, cleanup, err := a.newParallelRuntimeManager(preset.ID, "resolver-discovery", runtimemgr.Callbacks{
		OnResolverState: func(state model.ResolverRuntimeState) {
			select {
			case updates <- parallelResolverUpdate{presetID: preset.ID, state: state}:
			case <-ctx.Done():
			}
		},
		OnProgress: func(progress model.ConnectionProgress) {
			select {
			case updates <- parallelResolverUpdate{presetID: preset.ID, progress: progress, hasProgress: true}:
			case <-ctx.Done():
			}
			a.updateParallelTestState(runID, func(state *model.ParallelTestState) {
				if state.Phase == parallelPhaseResolvers && progress.Valid > len(state.Resolvers) {
					state.Message = fmt.Sprintf("Finding resolvers: %d valid reported", progress.Valid)
				}
			})
		},
		OnError: func(message string) {
			mu.Lock()
			lastRuntimeError = strings.TrimSpace(message)
			mu.Unlock()
		},
	})
	if err != nil {
		return err
	}
	defer cleanup()

	cfg, err := buildParallelLaunchConfig(baseState, preset, nil)
	if err != nil {
		return err
	}
	err = manager.Start(ctx, cfg)
	if err != nil {
		mu.Lock()
		runtimeError := lastRuntimeError
		mu.Unlock()
		return parallelRuntimeError(err, runtimeError)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (a *App) runParallelCandidateStartup(ctx context.Context, baseState model.AppState, preset parallelTestPreset, resolvers []string) model.ParallelTestCandidateResult {
	return a.runParallelCandidate(ctx, baseState, preset, resolvers, false)
}

func (a *App) runParallelCandidateSpeed(ctx context.Context, baseState model.AppState, preset parallelTestPreset, resolvers []string) model.ParallelTestCandidateResult {
	return a.runParallelCandidate(ctx, baseState, preset, resolvers, true)
}

func (a *App) runParallelCandidate(ctx context.Context, baseState model.AppState, preset parallelTestPreset, resolvers []string, speedTest bool) model.ParallelTestCandidateResult {
	result := model.ParallelTestCandidateResult{
		ID:     preset.ID,
		Name:   preset.Name,
		Status: parallelCandidateFailed,
	}

	var mu sync.Mutex
	var lastResolverState model.ResolverRuntimeState
	var lastProgress model.ConnectionProgress
	var peakStats model.TrafficStats
	var lastRuntimeError string
	manager, cleanup, err := a.newParallelRuntimeManager(preset.ID, "candidate-test", runtimemgr.Callbacks{
		OnResolverState: func(state model.ResolverRuntimeState) {
			mu.Lock()
			lastResolverState = state
			mu.Unlock()
		},
		OnProgress: func(progress model.ConnectionProgress) {
			mu.Lock()
			lastProgress = progress
			mu.Unlock()
		},
		OnStats: func(stats model.TrafficStats) {
			mu.Lock()
			if stats.DownloadSpeedBytesPerSecond > peakStats.DownloadSpeedBytesPerSecond {
				peakStats = stats
			}
			mu.Unlock()
		},
		OnError: func(message string) {
			mu.Lock()
			lastRuntimeError = strings.TrimSpace(message)
			mu.Unlock()
		},
	})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer cleanup()

	cfg, err := buildParallelLaunchConfig(baseState, preset, resolvers)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	started := time.Now()
	err = manager.Start(ctx, cfg)
	duration := time.Since(started)
	result.StartDurationMs = duration.Milliseconds()
	result.RTTMs = result.StartDurationMs
	mu.Lock()
	resolverState := lastResolverState
	progress := lastProgress
	stats := peakStats
	runtimeError := lastRuntimeError
	mu.Unlock()
	result.Stability = parallelCandidateStability(resolverState, progress)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			result.Status = parallelCandidateCancelled
		}
		result.Score = parallelCandidateScore(result.Stability, duration, 0)
		result.Error = parallelRuntimeError(err, runtimeError).Error()
		return result
	}

	if speedTest {
		speedResult := parallelCandidateDownloadSpeed(ctx, cfg)
		result.DownloadBytesPerSecond = maxInt64(speedResult.bytesPerSecond, stats.DownloadSpeedBytesPerSecond)
		result.SpeedTestBytes = speedResult.bytes
		result.SpeedTestDurationMs = speedResult.duration.Milliseconds()
		if speedResult.err != nil && result.DownloadBytesPerSecond <= 0 {
			result.SpeedTestError = speedResult.err.Error()
		}
	}
	result.Status = parallelCandidateConnected
	if result.Stability <= 0 {
		result.Stability = 100
	}
	result.Score = parallelCandidateScore(result.Stability, duration, result.DownloadBytesPerSecond)
	return result
}

func parallelRuntimeError(err error, runtimeMessage string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	runtimeMessage = strings.TrimSpace(runtimeMessage)
	if runtimeMessage == "" || strings.Contains(err.Error(), runtimeMessage) {
		return err
	}
	return fmt.Errorf("%s: %w", runtimeMessage, err)
}

func parallelCandidateDownloadSpeed(ctx context.Context, cfg storm.LaunchConfig) parallelSpeedTestResult {
	speedCtx, cancel := context.WithTimeout(ctx, parallelSpeedTestTimeout)
	defer cancel()

	transport, err := parallelSpeedTestTransport(cfg)
	if err != nil {
		return parallelSpeedTestResult{err: err}
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport}
	var lastErr error
	for _, endpoint := range parallelSpeedTestURLs {
		result := downloadSpeedFromURL(speedCtx, client, endpoint, parallelSpeedTestMaxBytes)
		if result.bytesPerSecond > 0 {
			return result
		}
		if result.err != nil {
			lastErr = result.err
		}
		if speedCtx.Err() != nil {
			return parallelSpeedTestResult{err: speedCtx.Err()}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("download speed test returned no data")
	}
	return parallelSpeedTestResult{err: lastErr}
}

func downloadSpeedFromURL(ctx context.Context, client *http.Client, endpoint string, maxBytes int64) parallelSpeedTestResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return parallelSpeedTestResult{err: err}
	}
	req.Header.Set("Cache-Control", "no-cache")

	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return parallelSpeedTestResult{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return parallelSpeedTestResult{err: fmt.Errorf("download speed test returned HTTP %d", resp.StatusCode)}
	}

	bytes, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	duration := time.Since(started)
	result := parallelSpeedTestResult{
		bytes:    bytes,
		duration: duration,
		err:      copyErr,
	}
	if bytes > 0 && duration > 0 {
		result.bytesPerSecond = int64(float64(bytes) / duration.Seconds())
	}
	if result.bytesPerSecond > 0 {
		result.err = nil
	}
	return result
}

func parallelSpeedTestTransport(cfg storm.LaunchConfig) (*http.Transport, error) {
	host := proxyLoopbackHost(cfg.PublicListenIP)
	port := cfg.PublicListenPort
	if port <= 0 {
		host = proxyLoopbackHost(cfg.Settings.ListenIP)
		port = cfg.Settings.ListenPort
	}
	if port <= 0 {
		return nil, errors.New("proxy endpoint is unavailable for speed test")
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	inboundType := strings.ToLower(strings.TrimSpace(cfg.Settings.SingBoxInboundType))
	if inboundType == "" {
		inboundType = "mixed"
	}
	if cfg.CoreEnabled && (inboundType == "mixed" || inboundType == "http") {
		proxyURL := &url.URL{Scheme: "http", Host: address}
		if cfg.Settings.SOCKS5Authentication {
			proxyURL.User = url.UserPassword(cfg.Settings.SOCKSUsername, cfg.Settings.SOCKSPassword)
		}
		return &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			TLSHandshakeTimeout:   4 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			IdleConnTimeout:       2 * time.Second,
		}, nil
	}
	var auth *proxy.Auth
	if cfg.Settings.SOCKS5Authentication {
		auth = &proxy.Auth{User: cfg.Settings.SOCKSUsername, Password: cfg.Settings.SOCKSPassword}
	}
	dialer, err := proxy.SOCKS5("tcp", address, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		DialContext:           socksDialContext(dialer),
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       2 * time.Second,
	}, nil
}

func socksDialContext(dialer proxy.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		type dialResult struct {
			conn net.Conn
			err  error
		}
		resultCh := make(chan dialResult, 1)
		go func() {
			conn, err := dialer.Dial(network, address)
			resultCh <- dialResult{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-resultCh:
			return result.conn, result.err
		}
	}
}

func proxyLoopbackHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1"
	}
	return host
}

func runParallelTestCandidates(
	ctx context.Context,
	baseState model.AppState,
	presets []parallelTestPreset,
	resolvers []string,
	batchSize int,
	runner parallelCandidateRunner,
	onUpdate func(model.ParallelTestCandidateResult),
) []model.ParallelTestCandidateResult {
	if batchSize <= 0 {
		batchSize = parallelCandidateBatchSize
	}
	results := make([]model.ParallelTestCandidateResult, 0, len(presets))
	for _, preset := range presets {
		results = append(results, model.ParallelTestCandidateResult{ID: preset.ID, Name: preset.Name, Status: parallelCandidatePending})
	}
	for start := 0; start < len(presets) && ctx.Err() == nil; start += batchSize {
		end := start + batchSize
		if end > len(presets) {
			end = len(presets)
		}
		var wg sync.WaitGroup
		resultCh := make(chan model.ParallelTestCandidateResult, end-start)
		for _, preset := range presets[start:end] {
			preset := preset
			running := model.ParallelTestCandidateResult{ID: preset.ID, Name: preset.Name, Status: parallelCandidateRunning}
			replaceParallelCandidate(results, running)
			if onUpdate != nil {
				onUpdate(running)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ctx.Err() != nil {
					resultCh <- model.ParallelTestCandidateResult{ID: preset.ID, Name: preset.Name, Status: parallelCandidateCancelled, Error: ctx.Err().Error()}
					return
				}
				resultCh <- runner(ctx, baseState, preset, resolvers)
			}()
		}
		wg.Wait()
		close(resultCh)
		for result := range resultCh {
			replaceParallelCandidate(results, result)
			if onUpdate != nil {
				onUpdate(result)
			}
		}
	}
	return results
}

func (a *App) newParallelRuntimeManager(presetID, phase string, callbacks runtimemgr.Callbacks) (parallelRuntimeManager, func(), error) {
	runtimeRoot := ""
	if configDir, err := appConfigDir(); err == nil {
		runtimeRoot = filepath.Join(configDir, "runtime", parallelRuntimeDirName)
	}
	if runtimeRoot == "" {
		runtimeRoot = filepath.Join(os.TempDir(), "whitevpn-desktop", parallelRuntimeDirName)
	}
	if err := os.MkdirAll(runtimeRoot, 0o755); err != nil {
		return nil, func() {}, err
	}
	runtimeDir, err := os.MkdirTemp(runtimeRoot, sanitizeParallelPathPart(presetID)+"-"+sanitizeParallelPathPart(phase)+"-")
	if err != nil {
		return nil, func() {}, err
	}
	factory := a.runtimeManagerFactory
	if factory == nil {
		factory = func(runtimeDir string, callbacks runtimemgr.Callbacks) parallelRuntimeManager {
			return runtimemgr.NewManager(runtimeManagerOptions(runtimeDir), callbacks)
		}
	}
	manager := factory(runtimeDir, callbacks)
	cleanup := func() {
		if manager != nil {
			_ = manager.Stop()
		}
		_ = os.RemoveAll(runtimeDir)
	}
	return manager, cleanup, nil
}

func buildParallelLaunchConfig(baseState model.AppState, preset parallelTestPreset, resolvers []string) (storm.LaunchConfig, error) {
	settings, err := temporaryParallelSettings(preset.Settings)
	if err != nil {
		return storm.LaunchConfig{}, err
	}
	state := profiles.NormalizeState(baseState)
	if len(resolvers) > 0 {
		state = stateWithParallelResolvers(state, resolvers)
	}
	return storm.BuildLaunchConfigWithSettings(state, settings)
}

func temporaryParallelSettings(settings model.SettingsProfile) (model.SettingsProfile, error) {
	settings = profiles.NormalizeSettingsProfile(settings)
	listenPort, err := freeLocalTCPPort()
	if err != nil {
		return settings, err
	}
	stormPort, err := freeLocalTCPPort()
	if err != nil {
		return settings, err
	}
	for stormPort == listenPort {
		stormPort, err = freeLocalTCPPort()
		if err != nil {
			return settings, err
		}
	}
	settings.ListenIP = "127.0.0.1"
	settings.ListenPort = listenPort
	settings.StormDNSListenIP = "127.0.0.1"
	settings.StormDNSListenPort = stormPort
	settings.LocalDNSEnabled = false
	settings.SingBoxSetSystemProxy = false
	return profiles.NormalizeSettingsProfile(settings), nil
}

func freeLocalTCPPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func stateWithParallelResolvers(state model.AppState, resolvers []string) model.AppState {
	resolverProfile := model.ResolverProfile{
		ID:             parallelResolverProfileID,
		Name:           "Parallel test resolvers",
		ResolverSource: "inline",
		ResolverText:   strings.Join(dedupeStrings(resolvers), "\n"),
	}
	state.ConnectionProfiles = append([]model.ConnectionProfile(nil), state.ConnectionProfiles...)
	state.ResolverProfiles = append([]model.ResolverProfile(nil), state.ResolverProfiles...)
	state.ResolverProfiles = append(state.ResolverProfiles, resolverProfile)
	state.SelectedResolverProfileID = resolverProfile.ID
	for idx := range state.ConnectionProfiles {
		if state.ConnectionProfiles[idx].ID == state.SelectedConnectionProfileID {
			state.ConnectionProfiles[idx].ResolverProfileID = resolverProfile.ID
			break
		}
	}
	return state
}

func (a *App) selectParallelWinnerPreset(preset parallelTestPreset) (model.SettingsProfile, bool, error) {
	a.mu.Lock()
	for _, existing := range a.state.SettingsProfiles {
		if settingsProfileNameKey(existing.Name) == settingsProfileNameKey(preset.Name) {
			a.state.SelectedSettingsProfileID = existing.ID
			settings := profiles.NormalizeSettingsProfile(existing)
			next, err := a.saveLocked()
			a.mu.Unlock()
			if err == nil {
				a.emit("app:state", next)
			}
			return settings, true, err
		}
	}
	a.mu.Unlock()
	return profiles.NormalizeSettingsProfile(preset.Settings), false, nil
}

func commonResolversFromReports(reports map[string]model.ResolverRuntimeState, presets []parallelTestPreset, target int) []string {
	if len(presets) == 0 || len(reports) < len(presets) {
		return nil
	}
	counts := map[string]int{}
	var order []string
	for idx, preset := range presets {
		report, ok := reports[preset.ID]
		if !ok {
			return nil
		}
		resolvers := resolverCandidatesFromState(report)
		if idx == 0 {
			order = append(order, resolvers...)
		}
		for _, resolver := range resolvers {
			counts[resolver]++
		}
	}
	out := make([]string, 0, target)
	for _, resolver := range order {
		if counts[resolver] == len(presets) {
			out = append(out, resolver)
			if len(out) >= target {
				return out
			}
		}
	}
	if len(out) >= target {
		return out
	}
	all := make([]string, 0, len(counts))
	for resolver, count := range counts {
		if count == len(presets) && !containsString(out, resolver) {
			all = append(all, resolver)
		}
	}
	sort.Strings(all)
	for _, resolver := range all {
		out = append(out, resolver)
		if len(out) >= target {
			break
		}
	}
	return out
}

func resolverCandidatesFromState(state model.ResolverRuntimeState) []string {
	resolvers := append([]string(nil), state.ValidResolvers...)
	if len(resolvers) == 0 {
		resolvers = append(resolvers, state.ActiveResolvers...)
	}
	return dedupeStrings(resolvers)
}

func bestParallelCandidate(results []model.ParallelTestCandidateResult) (model.ParallelTestCandidateResult, bool) {
	connected := topParallelCandidates(results, 1)
	if len(connected) == 0 {
		return model.ParallelTestCandidateResult{}, false
	}
	return connected[0], true
}

func topParallelCandidates(results []model.ParallelTestCandidateResult, limit int) []model.ParallelTestCandidateResult {
	if limit <= 0 {
		return nil
	}
	connected := make([]model.ParallelTestCandidateResult, 0, len(results))
	for _, result := range results {
		if result.Status == parallelCandidateConnected {
			connected = append(connected, result)
		}
	}
	sort.SliceStable(connected, func(i, j int) bool { return parallelCandidateBetter(connected[i], connected[j]) })
	if len(connected) > limit {
		return connected[:limit]
	}
	return connected
}

func parallelCandidateBetter(left, right model.ParallelTestCandidateResult) bool {
	if math.Abs(left.Stability-right.Stability) > 0.5 {
		return left.Stability > right.Stability
	}
	if left.DownloadBytesPerSecond != right.DownloadBytesPerSecond {
		return left.DownloadBytesPerSecond > right.DownloadBytesPerSecond
	}
	if left.Score != right.Score {
		return left.Score > right.Score
	}
	if left.StartDurationMs != right.StartDurationMs {
		return left.StartDurationMs < right.StartDurationMs
	}
	return left.Name < right.Name
}

func presetsFromCandidateResults(presets []parallelTestPreset, candidates []model.ParallelTestCandidateResult) []parallelTestPreset {
	out := make([]parallelTestPreset, 0, len(candidates))
	for _, candidate := range candidates {
		if preset, ok := presetByID(presets, candidate.ID); ok {
			out = append(out, preset)
		}
	}
	return out
}

func parallelCandidateStability(state model.ResolverRuntimeState, progress model.ConnectionProgress) float64 {
	valid := maxInt(maxInt(state.ValidCount, len(state.ValidResolvers)), progress.Valid)
	rejected := maxInt(state.RejectedCount, progress.Rejected)
	total := maxInt(state.TotalCount, progress.Total)
	if total <= 0 {
		total = valid + rejected
	}
	if total <= 0 {
		return 0
	}
	value := (float64(valid) / float64(total)) * 100
	if value > 100 {
		value = 100
	}
	return math.Round(value*100) / 100
}

func parallelCandidateScore(stability float64, duration time.Duration, downloadBytesPerSecond int64) int {
	startupScore := 15.0 - math.Min(duration.Seconds(), 30)*(15.0/30.0)
	if startupScore < 0 {
		startupScore = 0
	}
	downloadScore := 0.0
	if downloadBytesPerSecond > 0 {
		mbps := float64(downloadBytesPerSecond*8) / 1_000_000
		downloadScore = math.Min(25, math.Log1p(mbps)/math.Log1p(100)*25)
	}
	score := int(math.Round(stability*0.60 + downloadScore + startupScore))
	return clampInt(score, 0, 100)
}

func replaceParallelCandidate(results []model.ParallelTestCandidateResult, next model.ParallelTestCandidateResult) {
	for idx := range results {
		if results[idx].ID == next.ID {
			results[idx] = next
			return
		}
	}
}

func updateParallelCandidate(state *model.ParallelTestState, next model.ParallelTestCandidateResult) {
	for idx := range state.Candidates {
		if state.Candidates[idx].ID == next.ID {
			state.Candidates[idx] = next
			return
		}
	}
	state.Candidates = append(state.Candidates, next)
}

func countParallelCandidates(candidates []model.ParallelTestCandidateResult, match func(model.ParallelTestCandidateResult) bool) int {
	count := 0
	for _, candidate := range candidates {
		if match(candidate) {
			count++
		}
	}
	return count
}

func (a *App) updateParallelTestState(runID int64, mutate func(*model.ParallelTestState)) bool {
	a.parallelMu.Lock()
	if a.parallelRunID != runID || a.parallelState.Status != model.ParallelTestRunning {
		a.parallelMu.Unlock()
		return false
	}
	mutate(&a.parallelState)
	state := cloneParallelTestState(a.parallelState)
	a.parallelMu.Unlock()
	a.emit("parallel-test:state", state)
	return true
}

func (a *App) finishParallelTest(runID int64, status, phase, message string) {
	var cancel context.CancelFunc
	a.parallelMu.Lock()
	if a.parallelRunID != runID {
		a.parallelMu.Unlock()
		return
	}
	if a.parallelState.Status == model.ParallelTestCancelled && status != model.ParallelTestCancelled {
		a.parallelMu.Unlock()
		return
	}
	cancel = a.parallelCancel
	a.parallelCancel = nil
	a.parallelState.Status = status
	a.parallelState.Phase = phase
	a.parallelState.Message = message
	if status == model.ParallelTestFailed {
		a.parallelState.Error = message
	} else {
		a.parallelState.Error = ""
	}
	a.parallelState.Running = 0
	if status == model.ParallelTestCompleted {
		a.parallelState.Completed = a.parallelState.Total
	}
	a.parallelState.FinishedAt = time.Now().UnixMilli()
	state := cloneParallelTestState(a.parallelState)
	a.parallelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.emit("parallel-test:state", state)
}

func cloneParallelTestState(state model.ParallelTestState) model.ParallelTestState {
	state.Resolvers = append([]string(nil), state.Resolvers...)
	state.Candidates = append([]model.ParallelTestCandidateResult(nil), state.Candidates...)
	return state
}

func presetByID(presets []parallelTestPreset, id string) (parallelTestPreset, bool) {
	for _, preset := range presets {
		if preset.ID == id {
			return preset, true
		}
	}
	return parallelTestPreset{}, false
}

func presetDisplayName(presets []parallelTestPreset, id string) string {
	if preset, ok := presetByID(presets, id); ok {
		return preset.Name
	}
	return id
}

func settingsProfilesByName(settingsProfiles []model.SettingsProfile) map[string]model.SettingsProfile {
	out := make(map[string]model.SettingsProfile, len(settingsProfiles))
	for _, profile := range settingsProfiles {
		key := settingsProfileNameKey(profile.Name)
		if key != "" {
			out[key] = profile
		}
	}
	return out
}

func settingsProfileNames(settingsProfiles []model.SettingsProfile) map[string]struct{} {
	out := make(map[string]struct{}, len(settingsProfiles))
	for _, profile := range settingsProfiles {
		key := settingsProfileNameKey(profile.Name)
		if key != "" {
			out[key] = struct{}{}
		}
	}
	return out
}

func settingsProfileNameKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func uniqueSettingsProfileID(settingsProfiles []model.SettingsProfile, base string) string {
	existing := make(map[string]struct{}, len(settingsProfiles))
	for _, profile := range settingsProfiles {
		existing[profile.ID] = struct{}{}
	}
	id := strings.TrimSpace(base)
	if id == "" {
		id = "settings-autotune"
	}
	if _, ok := existing[id]; !ok {
		return id
	}
	for attempt := 2; ; attempt++ {
		candidate := fmt.Sprintf("%s-%d", id, attempt)
		if _, ok := existing[candidate]; !ok {
			return candidate
		}
	}
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func sanitizeParallelPathPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "parallel"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	runtimemgr "whitevpn-desktop/internal/runtime"
	"whitevpn-desktop/internal/storm"
)

const connectionProfileTestTimeout = 75 * time.Second

func (a *App) TestConnectionProfile(profile model.ConnectionProfile, trustedResolvers []model.ConnectionTestResolver) (model.ConnectionTestResult, error) {
	result := model.ConnectionTestResult{
		ProfileID: strings.TrimSpace(profile.ID),
		Message:   "Not tested",
	}
	if strings.TrimSpace(profile.Domain) == "" {
		result.Message = "Domain is required"
		return result, nil
	}
	if strings.TrimSpace(profile.EncryptionKey) == "" {
		result.Message = "Encryption key is required"
		return result, nil
	}
	if a.parallelTestRunning() {
		return result, fmt.Errorf("parallel test is running")
	}

	a.mu.Lock()
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.Status != model.RuntimeFailed {
		a.mu.Unlock()
		return result, fmt.Errorf("stop the active connection before testing profiles")
	}
	baseState := profiles.NormalizeState(a.state)
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), connectionProfileTestTimeout)
	defer cancel()

	settings, ok := storm.SelectedSettings(baseState)
	if !ok {
		settings = model.DefaultSettingsProfile()
	}
	trusted, trustedOK := firstUsableConnectionTestResolver(trustedResolvers)
	settings = connectionProfileTestSettings(settings, trustedOK, trusted)
	testState := stateWithConnectionTestProfile(baseState, profile)

	var mu sync.Mutex
	var lastResolverState model.ResolverRuntimeState
	var lastProgress model.ConnectionProgress
	var lastRuntimeError string
	manager, cleanup, err := a.newParallelRuntimeManager(result.ProfileID, "connection-test", runtimemgr.Callbacks{
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
		OnError: func(message string) {
			mu.Lock()
			lastRuntimeError = strings.TrimSpace(message)
			mu.Unlock()
		},
	})
	if err != nil {
		result.Message = err.Error()
		return result, nil
	}
	defer cleanup()

	var resolverEndpoints []string
	if trustedOK {
		resolverEndpoints = []string{trusted.Endpoint}
	}
	cfg, err := buildConnectionTestLaunchConfig(testState, settings, resolverEndpoints, trustedOK)
	if err != nil {
		result.Message = err.Error()
		return result, nil
	}

	started := time.Now()
	err = manager.Start(ctx, cfg)
	result.LatencyMs = time.Since(started).Milliseconds()

	mu.Lock()
	resolverState := lastResolverState
	progress := lastProgress
	runtimeError := lastRuntimeError
	mu.Unlock()
	result.Resolvers = connectionTestResolversFromState(resolverState)
	if len(result.Resolvers) > 0 {
		result.Resolver = result.Resolvers[0].Endpoint
	}

	if err != nil {
		result.Message = connectionTestErrorMessage(err, runtimeError)
		return result, nil
	}

	resolverState = waitForConnectionTestResolverDetails(ctx, func() model.ResolverRuntimeState {
		mu.Lock()
		defer mu.Unlock()
		return lastResolverState
	})
	resolvers := connectionTestResolversFromState(resolverState)
	if len(resolvers) > 0 {
		result.Resolvers = resolvers
		result.Resolver = resolvers[0].Endpoint
	}
	result.OK = true
	result.Message = "Connected"
	if result.Resolver != "" {
		result.Message = "Connected via " + result.Resolver
	}
	if progress.Total > 0 && len(result.Resolvers) == 0 {
		result.Message = fmt.Sprintf("Connected after %d of %d resolver checks", progress.Completed, progress.Total)
	}
	return result, nil
}

func connectionTestErrorMessage(err error, runtimeError string) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Connection test timed out"
	}
	return parallelRuntimeError(err, runtimeError).Error()
}

func connectionProfileTestSettings(settings model.SettingsProfile, trusted bool, resolver model.ConnectionTestResolver) model.SettingsProfile {
	settings.ImportType = model.ImportTypeMasterDNS
	settings = profiles.NormalizeSettingsProfile(settings)
	settings.ConnectionStartupMode = model.ConnectionStartupModeStandard
	settings.UploadDuplication = 1
	if settings.DownloadDuplication < 1 {
		settings.DownloadDuplication = 1
	}
	settings.MTUStartupLossVerifyEnabled = false
	settings.MTURecheckEnabled = false
	if trusted {
		settings.AutoRemoveLowMTUServers = false
		settings.MinUploadMTU = resolver.UploadMTU
		settings.MaxUploadMTU = resolver.UploadMTU
		settings.MinDownloadMTU = resolver.DownloadMTU
		settings.MaxDownloadMTU = resolver.DownloadMTU
	}
	return profiles.NormalizeSettingsProfile(settings)
}

func stateWithConnectionTestProfile(state model.AppState, profile model.ConnectionProfile) model.AppState {
	state = profiles.NormalizeState(state)
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.ID == "" {
		profile.ID = "connection-test"
	}
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = "Connection"
	}
	profile.ImportType = model.NormalizeImportType(profile.ImportType)
	profile.Domain = strings.TrimSpace(strings.TrimSuffix(profile.Domain, "."))
	profile.EncryptionKey = strings.TrimSpace(profile.EncryptionKey)
	if profile.ResolverProfileID == "" {
		profile.ResolverProfileID = state.SelectedResolverProfileID
	}

	state.ConnectionProfiles = append([]model.ConnectionProfile(nil), state.ConnectionProfiles...)
	replaced := false
	for idx := range state.ConnectionProfiles {
		if state.ConnectionProfiles[idx].ID == profile.ID {
			state.ConnectionProfiles[idx] = profile
			replaced = true
			break
		}
	}
	if !replaced {
		state.ConnectionProfiles = append(state.ConnectionProfiles, profile)
	}
	state.SelectedConnectionProfileID = profile.ID
	if profile.ResolverProfileID != "" {
		state.SelectedResolverProfileID = profile.ResolverProfileID
	}
	return state
}

func buildConnectionTestLaunchConfig(state model.AppState, settings model.SettingsProfile, resolvers []string, skipInitialMTU bool) (storm.LaunchConfig, error) {
	tempSettings, err := temporaryParallelSettings(settings)
	if err != nil {
		return storm.LaunchConfig{}, err
	}
	if len(resolvers) > 0 {
		state = stateWithParallelResolvers(state, resolvers)
	}
	cfg, err := storm.BuildLaunchConfigWithSettings(state, tempSettings)
	if err != nil {
		return storm.LaunchConfig{}, err
	}
	cfg.SkipInitialMTUScan = skipInitialMTU
	return cfg, nil
}

func firstUsableConnectionTestResolver(resolvers []model.ConnectionTestResolver) (model.ConnectionTestResolver, bool) {
	for _, resolver := range resolvers {
		resolver.Endpoint = strings.TrimSpace(resolver.Endpoint)
		if resolver.Endpoint == "" || resolver.UploadMTU <= 0 || resolver.DownloadMTU <= 0 {
			continue
		}
		return resolver, true
	}
	return model.ConnectionTestResolver{}, false
}

func connectionTestResolversFromState(state model.ResolverRuntimeState) []model.ConnectionTestResolver {
	out := make([]model.ConnectionTestResolver, 0, len(state.ResolverDetails))
	seen := map[string]int{}
	addDetail := func(detail model.ResolverRuntimeDetail, activeOnly bool) {
		if activeOnly && !detail.Active {
			return
		}
		endpoint := strings.TrimSpace(detail.Resolver)
		if endpoint == "" || endpoint == "-" || (!detail.Active && !detail.Valid) {
			return
		}
		next := model.ConnectionTestResolver{
			Endpoint:       endpoint,
			UploadMTU:      detail.UploadMTU,
			DownloadMTU:    detail.DownloadMTU,
			UploadMTUChars: detail.UploadMTUChars,
		}
		if idx, ok := seen[endpoint]; ok {
			if out[idx].UploadMTU <= 0 && next.UploadMTU > 0 {
				out[idx].UploadMTU = next.UploadMTU
			}
			if out[idx].DownloadMTU <= 0 && next.DownloadMTU > 0 {
				out[idx].DownloadMTU = next.DownloadMTU
			}
			if out[idx].UploadMTUChars <= 0 && next.UploadMTUChars > 0 {
				out[idx].UploadMTUChars = next.UploadMTUChars
			}
			return
		}
		seen[endpoint] = len(out)
		out = append(out, next)
	}
	for _, detail := range state.ResolverDetails {
		addDetail(detail, true)
	}
	for _, detail := range state.ResolverDetails {
		addDetail(detail, false)
	}
	if len(out) > 0 {
		return out
	}
	for _, endpoint := range resolverCandidatesFromState(state) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = len(out)
		out = append(out, model.ConnectionTestResolver{Endpoint: endpoint})
	}
	return out
}

func waitForConnectionTestResolverDetails(ctx context.Context, snapshot func() model.ResolverRuntimeState) model.ResolverRuntimeState {
	deadline := time.Now().Add(750 * time.Millisecond)
	for {
		state := snapshot()
		for _, resolver := range connectionTestResolversFromState(state) {
			if resolver.Endpoint != "" && resolver.UploadMTU > 0 && resolver.DownloadMTU > 0 {
				return state
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return state
		}
		time.Sleep(50 * time.Millisecond)
	}
}

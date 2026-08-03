package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	runtimemgr "whitevpn-desktop/internal/runtime"
	"whitevpn-desktop/internal/storm"
)

type fakeParallelRuntimeManager struct {
	start     func(context.Context, storm.LaunchConfig) error
	startXray func(context.Context, runtimemgr.XrayLaunchConfig) error
	stop      func() error
}

func (m fakeParallelRuntimeManager) Start(ctx context.Context, cfg storm.LaunchConfig) error {
	if m.start != nil {
		return m.start(ctx, cfg)
	}
	return nil
}

func (m fakeParallelRuntimeManager) StartXray(ctx context.Context, cfg runtimemgr.XrayLaunchConfig) error {
	if m.startXray != nil {
		return m.startXray(ctx, cfg)
	}
	return nil
}

func (m fakeParallelRuntimeManager) Stop() error {
	if m.stop != nil {
		return m.stop()
	}
	return nil
}

func TestStartParallelTestRejectsRuntimeActive(t *testing.T) {
	app := &App{state: model.DefaultAppState(), parallelState: model.DefaultParallelTestState()}
	app.state.Runtime.Status = model.RuntimeConnected

	if _, err := app.StartParallelTest(nil); err == nil || !strings.Contains(err.Error(), "active connection") {
		t.Fatalf("expected active runtime rejection, got %v", err)
	}
}

func TestStartConnectionClearsFinishedParallelTest(t *testing.T) {
	var events []model.ParallelTestState
	app := &App{
		state: model.DefaultAppState(),
		parallelState: model.ParallelTestState{
			Status:     model.ParallelTestCancelled,
			Phase:      parallelPhaseResolvers,
			Message:    "Parallel test cancelled",
			StartedAt:  1,
			FinishedAt: 2,
			Candidates: []model.ParallelTestCandidateResult{
				{ID: "iran-default", Name: "Iran Default", Status: parallelCandidatePending},
			},
		},
		emitHook: func(name string, payload any) {
			if name == "parallel-test:state" {
				events = append(events, payload.(model.ParallelTestState))
			}
		},
	}

	_, _ = app.StartConnection()

	state := app.GetParallelTestState()
	if state.Status != model.ParallelTestIdle || len(state.Candidates) != 0 || state.StartedAt != 0 || state.FinishedAt != 0 {
		t.Fatalf("expected finished parallel state to be cleared, got %#v", state)
	}
	if len(events) != 1 || events[0].Status != model.ParallelTestIdle {
		t.Fatalf("expected idle parallel event, got %#v", events)
	}
}

func TestParallelTestPresetOptionsUseAutoTunePresets(t *testing.T) {
	state := model.DefaultAppState()
	options := parallelTestPresetOptions(state, nil)
	if len(options) != 10 {
		t.Fatalf("expected 10 auto-tune presets, got %d", len(options))
	}
	if options[0].Name != "Iran Default" || options[0].Settings.MinUploadMTU != 40 || options[0].Settings.MaxDownloadMTU != 3000 {
		t.Fatalf("unexpected first preset: %#v", options[0])
	}
	if options[8].Name != "Iran No Compression Max" || options[8].Settings.UploadCompression != 0 || options[8].Settings.DownloadCompression != 0 {
		t.Fatalf("unexpected no-compression preset: %#v", options[8])
	}
	filtered := parallelTestPresetOptions(state, []string{"iran-default", "iran-wide-range-max"})
	if len(filtered) != 2 || filtered[0].ID != "iran-default" || filtered[1].ID != "iran-wide-range-max" {
		t.Fatalf("unexpected filtered presets: %#v", filtered)
	}
}

func TestSaveParallelTestPresetsAddsMissingProfiles(t *testing.T) {
	app := &App{state: model.DefaultAppState(), store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))}

	next, err := app.SaveParallelTestPresets([]string{"iran-default", "iran-no-compression-max"})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.SettingsProfiles) != 3 {
		t.Fatalf("expected default plus 2 saved presets, got %#v", next.SettingsProfiles)
	}
	next, err = app.SaveParallelTestPresets([]string{"iran-default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.SettingsProfiles) != 3 {
		t.Fatalf("expected duplicate save to be ignored, got %#v", next.SettingsProfiles)
	}
}

func TestSaveParallelTestPresetsPreservesConnectedRuntime(t *testing.T) {
	app := &App{state: model.DefaultAppState(), store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))}
	app.state.Runtime = model.RuntimeStatus{
		Status:              model.RuntimeConnected,
		Message:             "Proxy is connected",
		ActiveConnectionID:  model.DefaultConnectionProfileID,
		ListenIP:            "127.0.0.1",
		ListenPort:          10886,
		AutoProfilePresetID: "iran-default",
		AutoProfileName:     "Iran Default",
	}

	next, err := app.SaveParallelTestPresets([]string{"iran-default"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Runtime.Status != model.RuntimeConnected {
		t.Fatalf("expected connected runtime to be preserved, got %#v", next.Runtime)
	}
	if next.Runtime.AutoProfilePresetID != "iran-default" || next.Runtime.AutoProfileName != "Iran Default" {
		t.Fatalf("expected auto profile metadata to be preserved, got %#v", next.Runtime)
	}
	if app.state.Runtime.Status != model.RuntimeConnected {
		t.Fatalf("expected app runtime to remain connected, got %#v", app.state.Runtime)
	}
}

func TestParallelTestPresetsFromSelectionIncludesSettingsAndBuiltIns(t *testing.T) {
	state := model.DefaultAppState()
	custom := model.DefaultSettingsProfile()
	custom.ID = "settings-custom"
	custom.Name = "Custom Reliable"
	custom.MinUploadMTU = 99
	state.SettingsProfiles = append(state.SettingsProfiles, custom)

	presets := parallelTestPresetsFromSelection(state, []string{"settings:settings-custom", "builtin:iran-default"})
	if len(presets) != 2 {
		t.Fatalf("expected 2 presets, got %#v", presets)
	}
	if presets[0].ID != "settings:settings-custom" || presets[0].Name != custom.Name || presets[0].Settings.MinUploadMTU != 99 {
		t.Fatalf("unexpected custom preset: %#v", presets[0])
	}
	if presets[1].ID != "iran-default" || presets[1].Name != "Iran Default" {
		t.Fatalf("unexpected built-in preset: %#v", presets[1])
	}
}

func TestSelectParallelWinnerPresetSelectsExistingSettingsProfileByName(t *testing.T) {
	app := &App{state: model.DefaultAppState(), store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))}
	profile := model.DefaultSettingsProfile()
	profile.ID = "settings-fast"
	profile.Name = "Iran Default"
	app.state.SettingsProfiles = append(app.state.SettingsProfiles, profile)

	settings, saved, err := app.selectParallelWinnerPreset(parallelTestPreset{ID: "iran-default", Name: profile.Name, Settings: model.DefaultSettingsProfile()})
	if err != nil {
		t.Fatal(err)
	}
	if !saved || settings.ID != profile.ID {
		t.Fatalf("expected existing settings profile to be selected, got %#v saved=%t", settings, saved)
	}
	if app.state.SelectedSettingsProfileID != profile.ID {
		t.Fatalf("expected selected settings profile %q, got %q", profile.ID, app.state.SelectedSettingsProfileID)
	}
}

func TestParallelResolverTargetUsesSelectedUploadDuplication(t *testing.T) {
	state := model.DefaultAppState()
	state.SettingsProfiles[0].UploadDuplication = 7

	if got := parallelResolverTargetForState(state); got != 7 {
		t.Fatalf("expected upload duplication resolver target, got %d", got)
	}

	state.SettingsProfiles[0].UploadDuplication = 1
	if got := parallelResolverTargetForState(state); got != 1 {
		t.Fatalf("expected minimum resolver target 1, got %d", got)
	}
}

func TestFindParallelTestResolversRunsSingleDiscoveryAndStopsAfterTarget(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "example.com"
	state.ConnectionProfiles[0].EncryptionKey = "secret"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8\n9.9.9.9\n4.4.4.4"
	target := parallelResolverTargetForState(state)

	var starts int64
	var discoveryResolvers string
	app := &App{
		state:         state,
		parallelRunID: 1,
		parallelState: model.ParallelTestState{
			Status:         model.ParallelTestRunning,
			Phase:          parallelPhaseResolvers,
			ResolverTarget: target,
		},
		runtimeManagerFactory: func(_ string, callbacks runtimemgr.Callbacks) parallelRuntimeManager {
			return fakeParallelRuntimeManager{
				start: func(ctx context.Context, cfg storm.LaunchConfig) error {
					atomic.AddInt64(&starts, 1)
					discoveryResolvers = cfg.Resolvers
					callbacks.OnResolverState(model.ResolverRuntimeState{
						ValidResolvers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4"},
						ValidCount:     4,
						ValidComplete:  true,
					})
					<-ctx.Done()
					return ctx.Err()
				},
			}
		},
	}

	resolvers, err := app.findParallelTestResolvers(context.Background(), 1, state, target)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&starts) != 1 {
		t.Fatalf("expected one resolver discovery runtime, got %d", starts)
	}
	if discoveryResolvers != state.ResolverProfiles[0].ResolverText {
		t.Fatalf("expected discovery to use selected resolver profile once, got %q", discoveryResolvers)
	}
	want := []string{"1.1.1.1"}
	if strings.Join(resolvers, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected resolvers: got %#v want %#v", resolvers, want)
	}
}

func TestFindParallelTestResolversProceedsWithOneWhenScanCompletes(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "example.com"
	state.ConnectionProfiles[0].EncryptionKey = "secret"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8"
	state.SettingsProfiles[0].UploadDuplication = 4

	app := &App{
		state:         state,
		parallelRunID: 1,
		parallelState: model.ParallelTestState{
			Status:         model.ParallelTestRunning,
			Phase:          parallelPhaseResolvers,
			ResolverTarget: parallelResolverTargetForState(state),
		},
		runtimeManagerFactory: func(_ string, callbacks runtimemgr.Callbacks) parallelRuntimeManager {
			return fakeParallelRuntimeManager{
				start: func(ctx context.Context, _ storm.LaunchConfig) error {
					callbacks.OnResolverState(model.ResolverRuntimeState{
						ValidResolvers: []string{"1.1.1.1"},
						ValidCount:     1,
						TotalCount:     2,
						RejectedCount:  1,
						PendingCount:   0,
						ValidComplete:  true,
					})
					callbacks.OnProgress(model.ConnectionProgress{Phase: "mtu", Completed: 2, Total: 2, Valid: 1, Rejected: 1})
					<-ctx.Done()
					return ctx.Err()
				},
			}
		},
	}

	resolvers, err := app.findParallelTestResolvers(context.Background(), 1, state, parallelResolverTargetForState(state))
	if err != nil {
		t.Fatal(err)
	}
	if len(resolvers) != 1 || resolvers[0] != "1.1.1.1" {
		t.Fatalf("expected one completed-scan resolver, got %#v", resolvers)
	}
}

func TestFindParallelTestResolversHasNoInternalTimeout(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "example.com"
	state.ConnectionProfiles[0].EncryptionKey = "secret"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"

	started := make(chan struct{})
	app := &App{
		state:         state,
		parallelRunID: 1,
		parallelState: model.ParallelTestState{
			Status:         model.ParallelTestRunning,
			Phase:          parallelPhaseResolvers,
			ResolverTarget: 1,
		},
		runtimeManagerFactory: func(_ string, _ runtimemgr.Callbacks) parallelRuntimeManager {
			return fakeParallelRuntimeManager{
				start: func(ctx context.Context, _ storm.LaunchConfig) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				},
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := app.findParallelTestResolvers(ctx, 1, state, 1)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("resolver discovery did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("resolver discovery returned before cancellation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver discovery did not stop after cancellation")
	}
}

func TestRunParallelCandidateHasNoInternalTimeoutAndCancels(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "example.com"
	state.ConnectionProfiles[0].EncryptionKey = "secret"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"
	preset := parallelTestPreset{ID: "slow", Name: "Slow", Settings: model.DefaultSettingsProfile()}

	started := make(chan struct{})
	app := &App{
		state: state,
		runtimeManagerFactory: func(_ string, _ runtimemgr.Callbacks) parallelRuntimeManager {
			return fakeParallelRuntimeManager{
				start: func(ctx context.Context, _ storm.LaunchConfig) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				},
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan model.ParallelTestCandidateResult, 1)
	go func() {
		done <- app.runParallelCandidate(ctx, state, preset, []string{"1.1.1.1"}, false)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("candidate test did not start")
	}
	select {
	case result := <-done:
		t.Fatalf("candidate returned before cancellation: %#v", result)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case result := <-done:
		if result.Status != parallelCandidateCancelled {
			t.Fatalf("expected cancelled candidate, got %#v", result)
		}
		if !strings.Contains(result.Error, context.Canceled.Error()) {
			t.Fatalf("expected cancellation error, got %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("candidate test did not stop after cancellation")
	}
}

func TestFinishParallelTestStoresFailureError(t *testing.T) {
	app := &App{
		parallelRunID: 1,
		parallelState: model.ParallelTestState{
			Status: model.ParallelTestRunning,
		},
	}

	app.finishParallelTest(1, model.ParallelTestFailed, parallelPhaseResolvers, "windows helper failed")

	state := app.GetParallelTestState()
	if state.Error != "windows helper failed" {
		t.Fatalf("expected failure error to be stored, got %#v", state)
	}
}

func TestParallelRuntimeErrorIncludesRuntimeMessage(t *testing.T) {
	err := parallelRuntimeError(errors.New("runtime exited before proxy port became ready"), "MasterDNS stopped unexpectedly")

	if err == nil || !strings.Contains(err.Error(), "MasterDNS stopped unexpectedly") || !strings.Contains(err.Error(), "runtime exited") {
		t.Fatalf("expected combined runtime error, got %v", err)
	}
}

func TestCommonResolversFromReportsFindsThreeSharedResolvers(t *testing.T) {
	presets := []parallelTestPreset{
		{ID: "balanced", Name: "Balanced"},
		{ID: "low-latency", Name: "Low latency"},
		{ID: "high-stability", Name: "High stability"},
	}
	reports := map[string]model.ResolverRuntimeState{
		"balanced":       {ValidResolvers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4"}},
		"low-latency":    {ValidResolvers: []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "7.7.7.7"}},
		"high-stability": {ValidResolvers: []string{"9.9.9.9", "8.8.8.8", "1.1.1.1"}},
	}

	got := commonResolversFromReports(reports, presets, 3)
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected common resolvers: got %#v want %#v", got, want)
	}
}

func TestRunParallelTestCandidatesHonorsBatchSizeAndFinishesAll(t *testing.T) {
	presets := []parallelTestPreset{
		{ID: "one", Name: "One"},
		{ID: "two", Name: "Two"},
		{ID: "three", Name: "Three"},
		{ID: "four", Name: "Four"},
		{ID: "five", Name: "Five"},
		{ID: "six", Name: "Six"},
		{ID: "seven", Name: "Seven"},
	}
	var current int64
	var maxConcurrent int64
	var finished int64
	runner := func(ctx context.Context, _ model.AppState, preset parallelTestPreset, _ []string) model.ParallelTestCandidateResult {
		now := atomic.AddInt64(&current, 1)
		for {
			maxSeen := atomic.LoadInt64(&maxConcurrent)
			if now <= maxSeen || atomic.CompareAndSwapInt64(&maxConcurrent, maxSeen, now) {
				break
			}
		}
		defer atomic.AddInt64(&current, -1)
		defer atomic.AddInt64(&finished, 1)
		time.Sleep(20 * time.Millisecond)
		return model.ParallelTestCandidateResult{ID: preset.ID, Name: preset.Name, Status: parallelCandidateConnected, Stability: 100}
	}

	results := runParallelTestCandidates(context.Background(), model.DefaultAppState(), presets, []string{"1.1.1.1"}, 3, runner, nil)

	if len(results) != len(presets) {
		t.Fatalf("expected %d results, got %d", len(presets), len(results))
	}
	if atomic.LoadInt64(&maxConcurrent) > 3 {
		t.Fatalf("expected max concurrency <= 3, got %d", maxConcurrent)
	}
	if atomic.LoadInt64(&finished) != int64(len(presets)) {
		t.Fatalf("expected every candidate to finish, got %d", finished)
	}
}

func TestBestParallelCandidatePrefersStabilityThenSpeed(t *testing.T) {
	winner, ok := bestParallelCandidate([]model.ParallelTestCandidateResult{
		{ID: "fast", Name: "Fast", Status: parallelCandidateConnected, Stability: 91, DownloadBytesPerSecond: 5_000_000, Score: 90, StartDurationMs: 300},
		{ID: "stable", Name: "Stable", Status: parallelCandidateConnected, Stability: 98, DownloadBytesPerSecond: 100_000, Score: 88, StartDurationMs: 1200},
		{ID: "failed", Name: "Failed", Status: parallelCandidateFailed, Stability: 100, Score: 100, StartDurationMs: 10},
	})
	if !ok || winner.ID != "stable" {
		t.Fatalf("expected stability winner, got %#v ok=%t", winner, ok)
	}

	winner, ok = bestParallelCandidate([]model.ParallelTestCandidateResult{
		{ID: "slow", Name: "Slow", Status: parallelCandidateConnected, Stability: 95, DownloadBytesPerSecond: 500_000, Score: 90, StartDurationMs: 500},
		{ID: "fast", Name: "Fast", Status: parallelCandidateConnected, Stability: 95.2, DownloadBytesPerSecond: 2_000_000, Score: 85, StartDurationMs: 2000},
	})
	if !ok || winner.ID != "fast" {
		t.Fatalf("expected download speed tie-break winner, got %#v ok=%t", winner, ok)
	}

	winner, ok = bestParallelCandidate([]model.ParallelTestCandidateResult{
		{ID: "slow", Name: "Slow", Status: parallelCandidateConnected, Stability: 95, DownloadBytesPerSecond: 1_000_000, Score: 90, StartDurationMs: 2000},
		{ID: "fast", Name: "Fast", Status: parallelCandidateConnected, Stability: 95.2, DownloadBytesPerSecond: 1_000_000, Score: 90, StartDurationMs: 500},
	})
	if !ok || winner.ID != "fast" {
		t.Fatalf("expected startup tie-break winner, got %#v ok=%t", winner, ok)
	}
}

func TestTopParallelCandidatesLimitsSpeedStageToThree(t *testing.T) {
	top := topParallelCandidates([]model.ParallelTestCandidateResult{
		{ID: "one", Name: "One", Status: parallelCandidateConnected, Stability: 98, Score: 80, StartDurationMs: 900},
		{ID: "two", Name: "Two", Status: parallelCandidateConnected, Stability: 97, Score: 85, StartDurationMs: 800},
		{ID: "three", Name: "Three", Status: parallelCandidateConnected, Stability: 96, Score: 90, StartDurationMs: 700},
		{ID: "four", Name: "Four", Status: parallelCandidateConnected, Stability: 80, Score: 99, StartDurationMs: 100},
		{ID: "failed", Name: "Failed", Status: parallelCandidateFailed, Stability: 100, Score: 100, StartDurationMs: 10},
	}, 3)

	if len(top) != 3 {
		t.Fatalf("expected top 3 candidates, got %#v", top)
	}
	if got := []string{top[0].ID, top[1].ID, top[2].ID}; strings.Join(got, ",") != "one,two,three" {
		t.Fatalf("unexpected top candidates: %#v", got)
	}
}

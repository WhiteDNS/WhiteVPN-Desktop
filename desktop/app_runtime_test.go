package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestHandleRuntimeStateFailedSetsTerminalProgress(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime = model.RuntimeStatus{
		Status:                model.RuntimeConnecting,
		Message:               "Starting MasterDNS",
		ActiveConnectionID:    model.DefaultConnectionProfileID,
		ListenIP:              "127.0.0.1",
		ListenPort:            2080,
		LocalProxyIP:          "127.0.0.1",
		PublicProxyIP:         "192.168.0.106",
		ResolverMTUScanPaused: true,
		AutoProfilePresetID:   "iran-default",
		AutoProfileName:       "Iran Default",
		Progress: model.ConnectionProgress{
			Phase:     "mtu",
			Percent:   10,
			Completed: 0,
			Total:     50,
		},
		ResolverState: model.ResolverRuntimeState{
			ActiveResolvers: []string{"1.1.1.1"},
			ActiveCount:     1,
			ActiveComplete:  true,
		},
		Stats: model.TrafficStats{
			DownloadBytes:               100,
			UploadBytes:                 50,
			DownloadSpeedBytesPerSecond: 10,
			UploadSpeedBytesPerSecond:   5,
			TotalDataUsageBytes:         150,
		},
	}

	app.handleRuntimeState(model.RuntimeFailed, "Target server is overloaded / unavailable.")
	runtimeState := app.GetAppState().Runtime

	if runtimeState.Status != model.RuntimeFailed {
		t.Fatalf("expected failed status, got %#v", runtimeState)
	}
	if runtimeState.ActiveConnectionID != "" {
		t.Fatalf("expected active connection to be cleared, got %#v", runtimeState)
	}
	if runtimeState.ResolverMTUScanPaused {
		t.Fatalf("expected MTU scan pause flag to be cleared, got %#v", runtimeState)
	}
	if runtimeState.ListenIP != "" || runtimeState.ListenPort != 0 {
		t.Fatalf("expected listen endpoint to be cleared, got %#v", runtimeState)
	}
	if runtimeState.LocalProxyIP != "" || runtimeState.PublicProxyIP != "" {
		t.Fatalf("expected proxy display IPs to be cleared, got %#v", runtimeState)
	}
	if runtimeState.AutoProfilePresetID != "" || runtimeState.AutoProfileName != "" {
		t.Fatalf("expected auto profile metadata to be cleared, got %#v", runtimeState)
	}
	if runtimeState.Progress.Phase != "failed" || runtimeState.Progress.Percent != 0 || runtimeState.Progress.Total != 0 {
		t.Fatalf("expected terminal failed progress, got %#v", runtimeState.Progress)
	}
	if !reflect.DeepEqual(runtimeState.ResolverState, model.ResolverRuntimeState{}) {
		t.Fatalf("expected resolver state to be cleared, got %#v", runtimeState.ResolverState)
	}
	if runtimeState.Stats != (model.TrafficStats{}) {
		t.Fatalf("expected traffic stats to be cleared, got %#v", runtimeState.Stats)
	}
}

func TestHandleLogCapsHistoryInNormalMode(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Logs = nil

	total := runtimeLogLimit + 200
	for i := 0; i < total; i++ {
		app.handleLog("line")
	}

	if got := len(app.state.Runtime.Logs); got != runtimeLogLimit {
		t.Fatalf("expected normal log history to be capped at %d lines, got %d", runtimeLogLimit, got)
	}
}

func TestHandleLogCapsHistoryInDebugMode(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Logs = nil
	app.state.SettingsProfiles[0].LogLevel = "DEBUG"

	total := runtimeLogLimit + 200
	for i := 0; i < total; i++ {
		app.handleLog("debug line")
	}

	if got := len(app.state.Runtime.Logs); got != runtimeLogLimit {
		t.Fatalf("expected debug log history to be capped at %d lines, got %d", runtimeLogLimit, got)
	}
}

func TestHandleLogEmitsIncrementalLogOnly(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	events := []string{}
	app.emitHook = func(name string, _ any) {
		events = append(events, name)
	}

	app.handleLog("line")

	if !reflect.DeepEqual(events, []string{"runtime:log"}) {
		t.Fatalf("expected incremental log event only, got %#v", events)
	}
}

func TestHandleLogSplitsRuntimeLogsByRuntimeType(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Logs = nil
	app.state.Runtime.MasterDNSLogs = nil
	app.state.Runtime.V2RayLogs = nil

	app.state.Runtime.RuntimeType = model.RuntimeTypeMasterDNS
	app.handleLog("masterdns log")
	app.state.Runtime.RuntimeType = model.RuntimeTypeV2Ray
	app.handleLog("v2ray log")

	runtimeState := app.GetAppState().Runtime
	if !reflect.DeepEqual(runtimeState.MasterDNSLogs, []string{"masterdns log"}) {
		t.Fatalf("unexpected MasterDNS logs: %#v", runtimeState.MasterDNSLogs)
	}
	if !reflect.DeepEqual(runtimeState.V2RayLogs, []string{"v2ray log"}) {
		t.Fatalf("unexpected V2Ray logs: %#v", runtimeState.V2RayLogs)
	}
	if !reflect.DeepEqual(runtimeState.Logs, []string{"v2ray log", "masterdns log"}) {
		t.Fatalf("unexpected combined logs: %#v", runtimeState.Logs)
	}
}

func TestHandleLogRedactsV2RayEndpointConfig(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.RuntimeType = model.RuntimeTypeV2Ray
	app.state.Runtime.Logs = nil
	app.state.Runtime.V2RayLogs = nil

	app.handleLog(`transport/internet/websocket: failed to dial to 108.162.192.75:443 > read tcp 192.168.0.141:14492->108.162.192.75:443 host_header="origin.example.com" tls_server_name="origin.example.com" request_path="/secret" GET https://edge.example.com:443/path`)

	got := app.GetAppState().Runtime.V2RayLogs[0]
	for _, secret := range []string{"108.162.192.75", "192.168.0.141", "origin.example.com", "/secret", "edge.example.com"} {
		if strings.Contains(got, secret) {
			t.Fatalf("expected endpoint config to be redacted, got %q", got)
		}
	}
	if !strings.Contains(got, "[redacted") {
		t.Fatalf("expected redaction marker, got %q", got)
	}
}

func TestClearRuntimeLogsForTypeOnlyClearsSelectedBuffer(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Logs = []string{"v2ray log", "masterdns log"}
	app.state.Runtime.MasterDNSLogs = []string{"masterdns log"}
	app.state.Runtime.V2RayLogs = []string{"v2ray log"}

	app.ClearRuntimeLogsForType(model.RuntimeTypeV2Ray)
	runtimeState := app.GetAppState().Runtime

	if len(runtimeState.V2RayLogs) != 0 {
		t.Fatalf("expected V2Ray logs to be cleared, got %#v", runtimeState.V2RayLogs)
	}
	if !reflect.DeepEqual(runtimeState.MasterDNSLogs, []string{"masterdns log"}) {
		t.Fatalf("expected MasterDNS logs to remain, got %#v", runtimeState.MasterDNSLogs)
	}
	if !reflect.DeepEqual(runtimeState.Logs, []string{"v2ray log", "masterdns log"}) {
		t.Fatalf("expected combined logs to remain, got %#v", runtimeState.Logs)
	}
}

func TestHandleRuntimeStateDisconnectedClearsLiveRuntimeState(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime = model.RuntimeStatus{
		Status:              model.RuntimeConnecting,
		RuntimeType:         model.RuntimeTypeMasterDNS,
		Message:             "Starting MasterDNS",
		ActiveConnectionID:  model.DefaultConnectionProfileID,
		ListenIP:            "127.0.0.1",
		ListenPort:          2080,
		LocalProxyIP:        "127.0.0.1",
		PublicProxyIP:       "192.168.0.106",
		AutoProfilePresetID: "iran-default",
		AutoProfileName:     "Iran Default",
		Progress: model.ConnectionProgress{
			Phase:     "mtu",
			Percent:   10,
			Completed: 1,
			Total:     20,
			Valid:     1,
		},
		ResolverState: model.ResolverRuntimeState{
			ActiveResolvers: []string{"1.1.1.1"},
			ValidResolvers:  []string{"1.1.1.1"},
			TotalCount:      1,
			ActiveCount:     1,
			ValidCount:      1,
			ActiveComplete:  true,
			ValidComplete:   true,
		},
		Stats: model.TrafficStats{
			DownloadBytes:               100,
			UploadBytes:                 50,
			DownloadSpeedBytesPerSecond: 10,
			UploadSpeedBytesPerSecond:   5,
			TotalDataUsageBytes:         150,
		},
	}

	app.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	runtimeState := app.GetAppState().Runtime

	if runtimeState.Status != model.RuntimeDisconnected {
		t.Fatalf("expected disconnected status, got %#v", runtimeState)
	}
	if runtimeState.RuntimeType != "" {
		t.Fatalf("expected runtime type to be cleared, got %#v", runtimeState)
	}
	if runtimeState.ActiveConnectionID != "" {
		t.Fatalf("expected active connection to be cleared, got %#v", runtimeState)
	}
	if runtimeState.ListenIP != "" || runtimeState.ListenPort != 0 {
		t.Fatalf("expected listen endpoint to be cleared, got %#v", runtimeState)
	}
	if runtimeState.LocalProxyIP != "" || runtimeState.PublicProxyIP != "" {
		t.Fatalf("expected proxy display IPs to be cleared, got %#v", runtimeState)
	}
	if runtimeState.AutoProfilePresetID != "" || runtimeState.AutoProfileName != "" {
		t.Fatalf("expected auto profile metadata to be cleared, got %#v", runtimeState)
	}
	if runtimeState.Progress != (model.ConnectionProgress{}) {
		t.Fatalf("expected stale progress to be cleared, got %#v", runtimeState.Progress)
	}
	if !reflect.DeepEqual(runtimeState.ResolverState, model.ResolverRuntimeState{}) {
		t.Fatalf("expected resolver state to be cleared, got %#v", runtimeState.ResolverState)
	}
	if runtimeState.Stats != (model.TrafficStats{}) {
		t.Fatalf("expected traffic stats to be cleared, got %#v", runtimeState.Stats)
	}
}

func TestHandleRuntimeLiveCallbacksIgnoredAfterTerminalState(t *testing.T) {
	testCases := []struct {
		name         string
		initialState model.RuntimeStatus
	}{
		{
			name: "disconnected",
			initialState: model.RuntimeStatus{
				Status: model.RuntimeDisconnected,
			},
		},
		{
			name: "failed",
			initialState: model.RuntimeStatus{
				Status:   model.RuntimeFailed,
				Progress: model.ConnectionProgress{Phase: "failed"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			app := &App{state: model.DefaultAppState()}
			app.state.Runtime = testCase.initialState

			app.handleProgress(model.ConnectionProgress{Phase: "mtu", Percent: 80, Completed: 8, Total: 10})
			app.handleStats(model.TrafficStats{
				DownloadBytes:               100,
				UploadBytes:                 50,
				DownloadSpeedBytesPerSecond: 10,
				UploadSpeedBytesPerSecond:   5,
				TotalDataUsageBytes:         150,
			})

			runtimeState := app.GetAppState().Runtime
			if runtimeState.Progress != testCase.initialState.Progress {
				t.Fatalf("expected progress callback to be ignored, got %#v", runtimeState.Progress)
			}
			if runtimeState.Stats != (model.TrafficStats{}) {
				t.Fatalf("expected stats callback to be ignored, got %#v", runtimeState.Stats)
			}
		})
	}
}

func TestBeginStoppingMarksARunningRuntime(t *testing.T) {
	for _, status := range []string{model.RuntimeConnecting, model.RuntimeConnected} {
		t.Run(status, func(t *testing.T) {
			app := &App{state: model.DefaultAppState()}
			app.state.Runtime.Status = status
			app.state.Runtime.Message = "Proxy listening on 127.0.0.1:7890"
			events := []string{}
			app.emitHook = func(name string, _ any) { events = append(events, name) }

			if !app.beginStopping() {
				t.Fatalf("expected a running runtime to be marked as stopping")
			}
			if got := app.GetAppState().Runtime.Status; got != model.RuntimeStopping {
				t.Fatalf("expected stopping status, got %q", got)
			}
			if !reflect.DeepEqual(events, []string{"runtime:state"}) {
				t.Fatalf("expected the interface to be told, got %#v", events)
			}
		})
	}
}

func TestBeginStoppingLeavesIdleRuntimeAlone(t *testing.T) {
	for _, status := range []string{model.RuntimeDisconnected, model.RuntimeFailed} {
		t.Run(status, func(t *testing.T) {
			app := &App{state: model.DefaultAppState()}
			app.state.Runtime.Status = status
			events := []string{}
			app.emitHook = func(name string, _ any) { events = append(events, name) }

			if app.beginStopping() {
				t.Fatalf("expected nothing to stop from %q", status)
			}
			if got := app.GetAppState().Runtime.Status; got != status {
				t.Fatalf("expected %q to be left alone, got %q", status, got)
			}
			if len(events) != 0 {
				t.Fatalf("expected no state a user was never in, got %#v", events)
			}
		})
	}
}

func TestCancelConnectStopsAnAttemptAndIsReportedAsDisconnected(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Status = model.RuntimeConnecting

	ctx, cancel := app.beginConnect()
	defer cancel()

	if !app.cancelConnect() {
		t.Fatal("expected the in-flight attempt to be cancelled")
	}
	if ctx.Err() == nil {
		t.Fatal("expected the attempt's context to be done")
	}
	if app.cancelConnect() {
		t.Fatal("expected nothing left to cancel")
	}

	// A session that finishes connecting after that must not be adopted, or the
	// engine would go on running behind a disconnected interface.
	if app.adoptSession(ctx, nil) {
		t.Fatal("expected a cancelled attempt to refuse its session")
	}

	app.reportConnectFailure(ctx, "context canceled")
	if got := app.GetAppState().Runtime.Status; got != model.RuntimeDisconnected {
		t.Fatalf("expected a stopped connect to end disconnected, got %q", got)
	}
}

func TestReportConnectFailureKeepsRealFailures(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Status = model.RuntimeConnecting

	ctx, cancel := app.beginConnect()
	defer cancel()

	app.reportConnectFailure(ctx, "no node carried traffic")
	runtimeState := app.GetAppState().Runtime
	if runtimeState.Status != model.RuntimeFailed {
		t.Fatalf("expected failed status, got %q", runtimeState.Status)
	}
	if runtimeState.Message != "no node carried traffic" {
		t.Fatalf("expected the reason to be kept, got %q", runtimeState.Message)
	}
}

func TestClearRuntimeLogsReturnsEmptyLogArray(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.Runtime.Logs = []string{"first log"}

	state := app.ClearRuntimeLogs()
	if state.Runtime.Logs == nil {
		t.Fatal("expected cleared logs to be an empty slice, got nil")
	}
	if len(state.Runtime.Logs) != 0 {
		t.Fatalf("expected logs to be empty, got %#v", state.Runtime.Logs)
	}

	raw, err := json.Marshal(state.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"logs":null`) {
		t.Fatalf("cleared logs serialized as null: %s", raw)
	}
	if !strings.Contains(string(raw), `"logs":[]`) {
		t.Fatalf("cleared logs should serialize as an empty array: %s", raw)
	}
}

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/storm"
	"whitevpn-desktop/internal/traffic"
)

func TestManagerStartsFakeStormDNSAndStopsCleanly(t *testing.T) {
	tempDir := t.TempDir()
	helper := buildFakeMasterDNSHelper(t, tempDir)
	xray := buildFakeXrayHelper(t, tempDir)
	stormPort := freePort(t)
	publicPort := freePort(t)

	var logs []string
	var states []string
	progressCh := make(chan model.ConnectionProgress, 4)
	manager := NewManager(
		Options{
			RuntimeDir:     filepath.Join(tempDir, "runtime"),
			BinaryPath:     helper,
			XrayBinaryPath: xray,
			StartTimeout:   5 * time.Second,
			StopTimeout:    2 * time.Second,
		},
		Callbacks{
			OnLog:      func(line string) { logs = append(logs, line) },
			OnState:    func(status string, _ string) { states = append(states, status) },
			OnProgress: func(next model.ConnectionProgress) { progressCh <- next },
		},
	)

	cfg := storm.LaunchConfig{
		Settings: model.SettingsProfile{
			ListenIP:   "127.0.0.1",
			ListenPort: publicPort,
		},
		MasterDNSSettings: model.SettingsProfile{
			ListenIP:   "127.0.0.1",
			ListenPort: stormPort,
		},
		CoreEnabled:      true,
		CoreConfig:       fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, publicPort),
		CoreProtocol:     "socks",
		PublicListenIP:   "127.0.0.1",
		PublicListenPort: publicPort,
		ClientTOML:       fmt.Sprintf("LISTEN_IP = \"127.0.0.1\"\nLISTEN_PORT = %d\n", stormPort),
		Resolvers:        "1.1.1.1\n",
	}
	if err := manager.Start(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !manager.IsRunning() {
		t.Fatal("expected manager to be running")
	}
	if err := manager.SetResolverMTUScanPaused(true); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	controlFile := manager.active.mtuScanControlFile
	manager.mu.Unlock()
	rawControl, err := os.ReadFile(controlFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(rawControl)) != "pause" {
		t.Fatalf("expected MTU scan control file to be paused, got %q", rawControl)
	}
	if err := manager.SetResolverMTUScanPaused(false); err != nil {
		t.Fatal(err)
	}
	rawControl, err = os.ReadFile(controlFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(rawControl)) != "resume" {
		t.Fatalf("expected MTU scan control file to be resumed, got %q", rawControl)
	}
	select {
	case progress := <-progressCh:
		if progress.Phase != "starting" {
			t.Fatalf("expected parsed progress, got %#v", progress)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for parsed progress")
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	if manager.IsRunning() {
		t.Fatal("expected manager to stop")
	}
	if len(logs) == 0 {
		t.Fatal("expected fake helper logs")
	}
	if states[len(states)-1] != model.RuntimeDisconnected {
		t.Fatalf("expected final disconnected state, got %v", states)
	}
}

func TestManagerStartsXrayOnlyAndStopsCleanly(t *testing.T) {
	tempDir := t.TempDir()
	xray := buildFakeXrayHelper(t, tempDir)
	publicPort := freePort(t)

	var states []string
	manager := NewManager(
		Options{
			RuntimeDir:     filepath.Join(tempDir, "runtime"),
			XrayBinaryPath: xray,
			StartTimeout:   5 * time.Second,
			StopTimeout:    2 * time.Second,
		},
		Callbacks{
			OnState: func(status string, _ string) { states = append(states, status) },
		},
	)

	cfg := XrayLaunchConfig{
		ProfileID:        "v2ray-1",
		Name:             "V2Ray",
		XrayConfig:       fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, publicPort),
		CoreProtocol:     "socks",
		PublicListenIP:   "127.0.0.1",
		PublicListenPort: publicPort,
	}
	if err := manager.StartXray(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !manager.IsRunning() {
		t.Fatal("expected manager to be running")
	}
	manager.mu.Lock()
	active := manager.active
	hasMasterDNS := active.cmd != nil
	hasXray := active.xrayCmd != nil && active.xrayCmd.Process != nil
	manager.mu.Unlock()
	if hasMasterDNS {
		t.Fatal("V2Ray runtime should not start MasterDNS")
	}
	if !hasXray {
		t.Fatal("expected xray process")
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	if len(states) == 0 || states[len(states)-1] != model.RuntimeDisconnected {
		t.Fatalf("expected final disconnected state, got %v", states)
	}
}

func TestMasterDNSLaunchEnvAddsFullInitialMTUScanOnlyWhenRequested(t *testing.T) {
	env := masterDNSLaunchEnv(storm.LaunchConfig{
		FullInitialMTUScan: true,
	}, "/tmp/scan-control")
	values := make(map[string]string, len(env))
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	if values["WHITEDNS_MTU_SCAN_CONTROL_FILE"] != "/tmp/scan-control" {
		t.Fatalf("missing scan control env: %#v", env)
	}
	if values[fullInitialMTUScanEnv] != "1" {
		t.Fatalf("missing full MTU scan env: %#v", env)
	}

	env = masterDNSLaunchEnv(storm.LaunchConfig{
		SkipInitialMTUScan: true,
	}, "/tmp/scan-control")
	values = make(map[string]string, len(env))
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	if values[skipInitialMTUScanEnv] != "1" {
		t.Fatalf("missing skip MTU scan env: %#v", env)
	}
	if _, ok := values[fullInitialMTUScanEnv]; ok {
		t.Fatalf("unexpected full scan env when only skip is requested: %#v", env)
	}

	env = masterDNSLaunchEnv(storm.LaunchConfig{}, "/tmp/scan-control")
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "WHITEDNS_SKIP_INITIAL_MTU") {
			t.Fatalf("unexpected deprecated MTU skip env: %#v", env)
		}
		if key == fullInitialMTUScanEnv {
			t.Fatalf("unexpected full scan env when not requested: %#v", env)
		}
	}
}

func TestManagerEmitsHostTrafficStatsFromSampler(t *testing.T) {
	tempDir := t.TempDir()
	helper := buildFakeMasterDNSHelper(t, tempDir)
	xray := buildFakeXrayHelper(t, tempDir)
	stormPort := freePort(t)
	publicPort := freePort(t)

	statsCh := make(chan model.TrafficStats, 8)
	manager := NewManager(
		Options{
			RuntimeDir:     filepath.Join(tempDir, "runtime"),
			BinaryPath:     helper,
			XrayBinaryPath: xray,
			TrafficSampler: &sequenceTrafficSampler{samples: []traffic.Counters{
				{RXBytes: 1000, TXBytes: 500},
				{RXBytes: 1800, TXBytes: 900},
				{RXBytes: 2400, TXBytes: 1200},
			}},
			TrafficInterval: 20 * time.Millisecond,
			StartTimeout:    5 * time.Second,
			StopTimeout:     2 * time.Second,
		},
		Callbacks{
			OnStats: func(stats model.TrafficStats) { statsCh <- stats },
		},
	)

	cfg := storm.LaunchConfig{
		Settings: model.SettingsProfile{
			ListenIP:   "127.0.0.1",
			ListenPort: publicPort,
		},
		MasterDNSSettings: model.SettingsProfile{
			ListenIP:   "127.0.0.1",
			ListenPort: stormPort,
		},
		CoreEnabled:      true,
		CoreConfig:       fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, publicPort),
		CoreProtocol:     "socks",
		PublicListenIP:   "127.0.0.1",
		PublicListenPort: publicPort,
		ClientTOML:       fmt.Sprintf("LISTEN_IP = \"127.0.0.1\"\nLISTEN_PORT = %d\n", stormPort),
		Resolvers:        "1.1.1.1\n",
	}
	if err := manager.Start(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case stats := <-statsCh:
			if stats.DownloadBytes == 1400 && stats.UploadBytes == 700 && stats.TotalDataUsageBytes == 2100 {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for host traffic stats")
		}
	}
}

func TestManagerWatchesMTUResolverStateFile(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, ".wd-test.mtu-resolvers.log")
	stateCh := make(chan model.ResolverRuntimeState, 4)
	manager := NewManager(
		Options{StopTimeout: time.Second},
		Callbacks{OnResolverState: func(state model.ResolverRuntimeState) { stateCh <- state }},
	)
	active := &activeProcess{mtuResolverStateFile: stateFile}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()
	manager.startMTUResolverStateMonitor(active)
	defer manager.stopMTUResolverStateMonitor(active)

	raw := strings.Join([]string{
		"WHITEDNS_MTU_STATE event=valid resolver=1.1.1.1 domain=v.example.com up=120 down=1300 up_chars=180",
		"WHITEDNS_MTU_STATE event=valid resolver=8.8.8.8 domain=v.example.com up=118 down=1280 up_chars=177",
		"WHITEDNS_MTU_STATE event=removed resolver=8.8.8.8 domain=v.example.com up=118 down=1280 up_chars=177 cause=Dropped by MTU Optimizer",
	}, "\n")
	if err := os.WriteFile(stateFile, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case state := <-stateCh:
		if state.ValidCount != 2 || state.ActiveCount != 1 || len(state.ActiveResolvers) != 1 || state.ActiveResolvers[0] != "1.1.1.1" {
			t.Fatalf("unexpected file-derived resolver state: %#v", state)
		}
		if len(state.ResolverDetails) != 2 {
			t.Fatalf("expected resolver details: %#v", state)
		}
		removed := state.ResolverDetails[1]
		if removed.Resolver != "8.8.8.8" || removed.UploadMTU != 118 || removed.DownloadMTU != 1280 || removed.UploadMTUChars != 177 || removed.Status != "valid" || removed.Active || !removed.Valid || removed.LastEvent != "removed" || removed.Cause != "Dropped by MTU Optimizer" {
			t.Fatalf("unexpected removed resolver detail: %#v", removed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for file-derived resolver state")
	}
}

func TestMergeResolverRuntimeStatePreservesFileDetails(t *testing.T) {
	logState := model.ResolverRuntimeState{
		ActiveResolvers: []string{"sample"},
		ValidResolvers:  []string{"sample"},
		TotalCount:      10,
		ActiveCount:     10,
		ValidCount:      10,
		ActiveComplete:  false,
		StandbyComplete: true,
		ValidComplete:   false,
	}
	fileState := model.ResolverRuntimeState{
		ActiveResolvers: []string{"1.1.1.1"},
		ValidResolvers:  []string{"1.1.1.1", "8.8.8.8"},
		ResolverDetails: []model.ResolverRuntimeDetail{
			{Resolver: "1.1.1.1", Domain: "v.example.com", Active: true, Valid: true, Status: "active", UploadMTU: 120, DownloadMTU: 1300, LastEvent: "valid"},
			{Resolver: "8.8.8.8", Domain: "v.example.com", Active: false, Valid: true, Status: "valid", UploadMTU: 118, DownloadMTU: 1280, LastEvent: "removed"},
		},
		ActiveCount:     1,
		ValidCount:      2,
		ActiveComplete:  true,
		StandbyComplete: true,
		ValidComplete:   true,
	}

	merged := mergeResolverRuntimeState(logState, fileState)
	if merged.TotalCount != 10 || merged.ActiveCount != 1 || merged.ValidCount != 2 {
		t.Fatalf("unexpected merged counts: %#v", merged)
	}
	if len(merged.ResolverDetails) != 2 || merged.ResolverDetails[1].Resolver != "8.8.8.8" {
		t.Fatalf("expected file resolver details to be preserved: %#v", merged)
	}
	if !resolverRuntimeStateEqual(merged, merged) {
		t.Fatal("expected equal resolver state")
	}
	changed := merged
	changed.ResolverDetails = append([]model.ResolverRuntimeDetail(nil), merged.ResolverDetails...)
	changed.ResolverDetails[1].UploadMTU = 117
	if resolverRuntimeStateEqual(merged, changed) {
		t.Fatal("expected resolver detail changes to affect equality")
	}
}

func TestManagerThrottlesRuntimeLogs(t *testing.T) {
	var logs []string
	manager := NewManager(
		Options{RuntimeDir: t.TempDir()},
		Callbacks{OnLog: func(line string) { logs = append(logs, line) }},
	)

	for i := 0; i < runtimeLogEventsPerSecond+25; i++ {
		manager.log(fmt.Sprintf("line-%d", i))
	}

	if got := len(logs); got != runtimeLogEventsPerSecond {
		t.Fatalf("expected %d emitted log lines, got %d", runtimeLogEventsPerSecond, got)
	}
	if logs[len(logs)-1] != fmt.Sprintf("line-%d", runtimeLogEventsPerSecond-1) {
		t.Fatalf("unexpected last unthrottled log: %q", logs[len(logs)-1])
	}

	manager.logWindowStart = manager.logWindowStart.Add(-time.Second)
	manager.log("after-window")

	if got := logs[len(logs)-2]; got != "Runtime log output throttled: dropped 25 lines in the last second" {
		t.Fatalf("expected throttling summary, got %q", got)
	}
	if got := logs[len(logs)-1]; got != "after-window" {
		t.Fatalf("expected next window log to pass, got %q", got)
	}
}

func TestManagerSuppressesBenignLocalProxyAbortLogs(t *testing.T) {
	var logs []string
	progressCh := make(chan model.ConnectionProgress, 1)
	manager := NewManager(
		Options{RuntimeDir: t.TempDir()},
		Callbacks{
			OnLog:      func(line string) { logs = append(logs, line) },
			OnProgress: func(next model.ConnectionProgress) { progressCh <- next },
		},
	)

	input := strings.NewReader(strings.Join([]string{
		"WD_PROGRESS phase=starting percent=5",
		"+0330 2026-05-26 08:27:33 ERROR [2572145833 1.50s] connection: connection upload closed: raw-read tcp4 127.0.0.1:10886->127.0.0.1:51717: An established connection was aborted by the software in your host machine.",
		"+0330 2026-05-26 08:27:34 ERROR [2572145834 1.51s] connection: real upstream failure",
	}, "\n"))
	manager.drainOutput(&activeProcess{}, input)

	for _, line := range logs {
		if strings.Contains(line, "connection upload closed") {
			t.Fatalf("benign local proxy abort should not be emitted: %q", line)
		}
	}
	if !slices.Contains(logs, "WD_PROGRESS phase=starting percent=5") {
		t.Fatalf("expected normal progress log to remain visible: %#v", logs)
	}
	if !slices.Contains(logs, "+0330 2026-05-26 08:27:34 ERROR [2572145834 1.51s] connection: real upstream failure") {
		t.Fatalf("expected real xray error to remain visible: %#v", logs)
	}

	select {
	case progress := <-progressCh:
		if progress.Phase != "starting" || progress.Percent != 5 {
			t.Fatalf("unexpected progress: %#v", progress)
		}
	default:
		t.Fatal("expected structured progress parsing to still run")
	}
}

func TestManagerParsesTrafficStatsFromRuntimeOutput(t *testing.T) {
	var logs []string
	statsCh := make(chan model.TrafficStats, 1)
	manager := NewManager(
		Options{RuntimeDir: t.TempDir()},
		Callbacks{
			OnLog:   func(line string) { logs = append(logs, line) },
			OnStats: func(stats model.TrafficStats) { statsCh <- stats },
		},
	)

	manager.drainOutput(&activeProcess{}, strings.NewReader("2026/05/20 [MasterDNS Client] [INFO] WD_STATS upload_bps=1234 upload_total=4096 download_bps=5678 download_total=8192\n"))

	select {
	case stats := <-statsCh:
		if stats.UploadSpeedBytesPerSecond != 1234 || stats.UploadBytes != 4096 {
			t.Fatalf("unexpected upload stats: %#v", stats)
		}
		if stats.DownloadSpeedBytesPerSecond != 5678 || stats.DownloadBytes != 8192 {
			t.Fatalf("unexpected download stats: %#v", stats)
		}
		if stats.TotalDataUsageBytes != 12288 {
			t.Fatalf("unexpected total stats: %#v", stats)
		}
	default:
		t.Fatal("expected runtime traffic stats to be emitted")
	}
	if len(logs) != 0 {
		t.Fatalf("machine traffic stats should not be emitted as user-facing logs: %#v", logs)
	}
}

func TestManagerPrefersRuntimeTrafficStatsOverHostSampler(t *testing.T) {
	statsCh := make(chan model.TrafficStats, 4)
	manager := NewManager(
		Options{
			TrafficSampler: &sequenceTrafficSampler{samples: []traffic.Counters{
				{RXBytes: 1000, TXBytes: 500},
				{RXBytes: 5000, TXBytes: 2500},
			}},
			TrafficInterval: 20 * time.Millisecond,
			StopTimeout:     time.Second,
		},
		Callbacks{OnStats: func(stats model.TrafficStats) { statsCh <- stats }},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	expected := model.TrafficStats{
		DownloadBytes:               8192,
		UploadBytes:                 4096,
		DownloadSpeedBytesPerSecond: 5678,
		UploadSpeedBytesPerSecond:   1234,
		TotalDataUsageBytes:         12288,
	}
	manager.recordLogTrafficStats(active, expected)
	manager.startTrafficMonitor(active, 123)
	defer manager.stopTrafficMonitor(active)

	select {
	case stats := <-statsCh:
		if stats != expected {
			t.Fatalf("unexpected runtime stats: %#v", stats)
		}
	default:
		t.Fatal("expected log traffic stats to be emitted")
	}

	select {
	case stats := <-statsCh:
		t.Fatalf("host sampler should not overwrite log traffic stats, got %#v", stats)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestManagerRuntimeConfigForcesAndPurgesMTUResolverStateFile(t *testing.T) {
	tempDir := t.TempDir()
	helper := buildFakeMasterDNSHelper(t, tempDir)
	xray := buildFakeXrayHelper(t, tempDir)
	stormPort := freePort(t)
	publicPort := freePort(t)

	manager := NewManager(
		Options{
			RuntimeDir:     filepath.Join(tempDir, "runtime"),
			BinaryPath:     helper,
			XrayBinaryPath: xray,
			TrafficSampler: traffic.SamplerFunc(func(context.Context, int) (traffic.Counters, error) { return traffic.Counters{}, traffic.ErrNoSample }),
			StartTimeout:   5 * time.Second,
			StopTimeout:    2 * time.Second,
		},
		Callbacks{},
	)
	cfg := storm.LaunchConfig{
		Connection: model.ConnectionProfile{
			Domain:           "v.example.com",
			EncryptionKey:    "key",
			EncryptionMethod: 1,
		},
		Settings: model.SettingsProfile{
			ListenIP:   "127.0.0.1",
			ListenPort: publicPort,
		},
		MasterDNSSettings: model.SettingsProfile{
			ListenIP:   "127.0.0.1",
			ListenPort: stormPort,
		},
		CoreEnabled:      true,
		CoreConfig:       fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, publicPort),
		CoreProtocol:     "socks",
		PublicListenIP:   "127.0.0.1",
		PublicListenPort: publicPort,
		Resolvers:        "1.1.1.1\n",
	}
	if err := manager.Start(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	configFile := manager.active.configFile
	stateFile := manager.active.mtuResolverStateFile
	manager.mu.Unlock()
	rawConfig, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	configText := string(rawConfig)
	if !strings.Contains(configText, `SAVE_MTU_SERVERS_TO_FILE = true`) || !strings.Contains(configText, stateFile) {
		t.Fatalf("runtime config did not force app-owned MTU resolver state file %q:\n%s", stateFile, configText)
	}
	if err := os.WriteFile(stateFile, []byte("WHITEDNS_MTU_STATE event=valid resolver=1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("expected MTU resolver state file to be purged, err=%v", err)
	}
}

func TestManagerReportsTrafficMonitorUnavailable(t *testing.T) {
	statusCh := make(chan string, 4)
	statsCh := make(chan model.TrafficStats, 4)
	manager := NewManager(
		Options{
			TrafficSampler:  &recoveringTrafficSampler{},
			TrafficInterval: 20 * time.Millisecond,
			StopTimeout:     time.Second,
		},
		Callbacks{
			OnTrafficStatus: func(message string) { statusCh <- message },
			OnStats:         func(stats model.TrafficStats) { statsCh <- stats },
		},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	manager.startTrafficMonitor(active, 123)
	defer manager.stopTrafficMonitor(active)

	select {
	case message := <-statusCh:
		if !strings.Contains(message, "permission denied") {
			t.Fatalf("unexpected monitor status: %q", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for traffic monitor status")
	}

	select {
	case message := <-statusCh:
		if message != "" {
			t.Fatalf("expected traffic monitor warning to clear after recovery, got %q", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for traffic monitor recovery")
	}

	select {
	case <-statsCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for recovered traffic stats")
	}
}

func TestManagerFindsPrebuiltClientInClientsDir(t *testing.T) {
	tempDir := t.TempDir()
	clientsDir := filepath.Join(tempDir, "clients")
	if err := os.MkdirAll(clientsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helper := buildFakeMasterDNSHelper(t, tempDir)
	target := filepath.Join(clientsDir, helperPlatformName())
	if err := os.Rename(helper, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(
		Options{
			RuntimeDir: filepath.Join(tempDir, "runtime"),
			ClientsDir: clientsDir,
		},
		Callbacks{},
	)
	resolved, err := manager.resolveBinary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resolved != target {
		t.Fatalf("expected %s, got %s", target, resolved)
	}
}

func TestManagerFindsPrebuiltClientFromEnvDir(t *testing.T) {
	tempDir := t.TempDir()
	clientsDir := filepath.Join(tempDir, "external-clients")
	if err := os.MkdirAll(clientsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helper := buildFakeMasterDNSHelper(t, tempDir)
	target := filepath.Join(clientsDir, "masterdns-client")
	if err := os.Rename(helper, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHITEDNS_CLIENTS_DIR", clientsDir)

	manager := NewManager(
		Options{
			RuntimeDir: filepath.Join(tempDir, "runtime"),
		},
		Callbacks{},
	)
	resolved, err := manager.resolveBinary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resolved != target {
		t.Fatalf("expected %s, got %s", target, resolved)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("expected helper to be made executable, mode=%v", info.Mode())
	}
}

func TestManagerExtractsEmbeddedClient(t *testing.T) {
	tempDir := t.TempDir()
	helper := buildFakeMasterDNSHelper(t, tempDir)
	raw, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(
		Options{
			RuntimeDir: filepath.Join(tempDir, "runtime"),
			EmbeddedClientsFS: fstest.MapFS{
				filepath.ToSlash(filepath.Join("clients", helperPlatformName())): &fstest.MapFile{
					Data: raw,
					Mode: 0o755,
				},
			},
		},
		Callbacks{},
	)
	resolved, err := manager.resolveBinary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(resolved, filepath.Join("helper", helperPlatformName())) {
		t.Fatalf("expected extracted helper path, got %s", resolved)
	}
	if !isExecutableFile(resolved) {
		t.Fatalf("expected extracted helper to be executable: %s", resolved)
	}
}

func TestManagerExtractsEmbeddedXrayCore(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(
		Options{
			RuntimeDir: filepath.Join(tempDir, "runtime"),
			EmbeddedCoresFS: fstest.MapFS{
				filepath.ToSlash(filepath.Join("cores", xrayPlatformName())): &fstest.MapFile{
					Data: []byte("#!/bin/sh\nexit 0\n"),
					Mode: 0o755,
				},
			},
		},
		Callbacks{},
	)
	resolved, ok := manager.extractEmbeddedXray(xrayPlatformName())
	if !ok {
		t.Fatal("expected embedded xray core to extract")
	}
	if !strings.HasSuffix(resolved, filepath.Join("helper", xrayPlatformName())) {
		t.Fatalf("expected extracted core path, got %s", resolved)
	}
	if !isExecutableFile(resolved) {
		t.Fatalf("expected extracted core to be executable: %s", resolved)
	}
}

func TestResolveBinaryMissingHelperMessageMentionsClients(t *testing.T) {
	manager := NewManager(
		Options{
			RuntimeDir: t.TempDir(),
		},
		Callbacks{},
	)
	_, err := manager.resolveBinary(context.Background())
	if err == nil {
		t.Fatal("expected missing helper error")
	}
	if !strings.Contains(err.Error(), "clients/") {
		t.Fatalf("expected clients/ hint, got %v", err)
	}
	if !strings.Contains(err.Error(), "Checked:") {
		t.Fatalf("expected checked paths, got %v", err)
	}
}

func TestStormDNSReadinessErrorUsesUnavailableMessage(t *testing.T) {
	err := stormDNSReadinessError(fmt.Errorf("proxy port did not open at 127.0.0.1:10887"))
	if err == nil {
		t.Fatal("expected readiness error")
	}
	if err.Error() != targetServerUnavailableMessage {
		t.Fatalf("expected unavailable message, got %q", err.Error())
	}
}

func TestWaitForPortHasNoStartupTimeout(t *testing.T) {
	manager := NewManager(
		Options{StartTimeout: 300 * time.Millisecond},
		Callbacks{},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- manager.waitForPort(ctx, "127.0.0.1", port, active)
	}()

	time.Sleep(450 * time.Millisecond)

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected wait to continue until port opened, got %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for port readiness")
	}
}

func TestStartupReadinessStopsAfterCompletedUnavailableMTUScan(t *testing.T) {
	manager := NewManager(
		Options{StartTimeout: 5 * time.Second},
		Callbacks{},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	manager.recordProgress(active, model.ConnectionProgress{Phase: "mtu", Completed: 10, Total: 10})
	manager.notifyTargetUnavailable(active)

	if !manager.startupReadinessFailed(active) {
		t.Fatal("expected completed unavailable scan to stop readiness wait")
	}
}

func TestStartupReadinessStopsAfterUnavailableMTUScanStalls(t *testing.T) {
	manager := NewManager(
		Options{StartTimeout: 100 * time.Millisecond},
		Callbacks{},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	manager.recordProgress(active, model.ConnectionProgress{Phase: "mtu", Percent: 10, Completed: 0, Total: 10})
	manager.notifyTargetUnavailable(active)
	if manager.startupReadinessFailed(active) {
		t.Fatal("fresh unavailable MTU progress should keep waiting")
	}

	stale := time.Now().Add(-manager.options.StartTimeout - time.Millisecond)
	manager.mu.Lock()
	active.targetUnavailableAt = stale
	active.progressChangedAt = stale
	manager.mu.Unlock()

	if !manager.startupReadinessFailed(active) {
		t.Fatal("expected stalled unavailable MTU scan to stop readiness wait")
	}
}

func TestStartupReadinessKeepsSessionInitRetriesAliveUntilStalled(t *testing.T) {
	manager := NewManager(
		Options{StartTimeout: 100 * time.Millisecond},
		Callbacks{},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	if _, ok := manager.recordSessionInitProgress(active, true); !ok {
		t.Fatal("expected session init progress to record")
	}
	manager.markTargetUnavailable(active, false)
	if manager.startupReadinessFailed(active) {
		t.Fatal("fresh session init retry progress should keep waiting")
	}

	stale := time.Now().Add(-manager.options.StartTimeout - time.Millisecond)
	manager.mu.Lock()
	active.targetUnavailableAt = stale
	active.progressChangedAt = stale
	manager.mu.Unlock()

	if !manager.startupReadinessFailed(active) {
		t.Fatal("expected stalled session init retry to stop readiness wait")
	}
}

func TestRecordProgressDoesNotRefreshUnchangedProgress(t *testing.T) {
	manager := NewManager(
		Options{StartTimeout: 100 * time.Millisecond},
		Callbacks{},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	progress := model.ConnectionProgress{Phase: "mtu", Percent: 10, Completed: 0, Total: 10}
	manager.recordProgress(active, progress)

	stale := time.Now().Add(-time.Second)
	manager.mu.Lock()
	active.progressChangedAt = stale
	manager.mu.Unlock()

	manager.recordProgress(active, progress)
	manager.mu.Lock()
	unchangedAt := active.progressChangedAt
	manager.mu.Unlock()
	if !unchangedAt.Equal(stale) {
		t.Fatalf("unchanged progress refreshed progressChangedAt: %v", unchangedAt)
	}

	progress.Completed = 1
	manager.recordProgress(active, progress)
	manager.mu.Lock()
	advancedAt := active.progressChangedAt
	manager.mu.Unlock()
	if !advancedAt.After(stale) {
		t.Fatalf("advanced progress did not refresh progressChangedAt: %v", advancedAt)
	}
}

func TestWaitForPortReturnsCanceledWhenStopped(t *testing.T) {
	manager := NewManager(
		Options{StartTimeout: 300 * time.Millisecond},
		Callbacks{},
	)
	active := &activeProcess{}
	manager.mu.Lock()
	manager.active = active
	manager.mu.Unlock()

	port := freePort(t)
	done := make(chan error, 1)
	go func() {
		done <- manager.waitForPort(context.Background(), "127.0.0.1", port, active)
	}()

	time.Sleep(100 * time.Millisecond)
	manager.mu.Lock()
	active.stopping = true
	manager.active = nil
	manager.mu.Unlock()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stopped readiness wait")
	}
}

func TestCleanupStaleLaunchFilesPurgesRuntimeFiles(t *testing.T) {
	tempDir := t.TempDir()
	files := []string{
		".wd-1.toml",
		".wd-1.resolvers",
		".wd-1.mtu-scan-control",
		".wd-1.mtu-resolvers.log",
		".wd-1.xray.json",
		".wd-1.stormdns.pid",
		".wd-1.xray.pid",
		"keep.log",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(tempDir, name), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := cleanupStaleLaunchFiles(tempDir, time.Second, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range files[:7] {
		if _, err := os.Stat(filepath.Join(tempDir, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, err=%v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(tempDir, "keep.log")); err != nil {
		t.Fatalf("expected unrelated log to remain: %v", err)
	}
}

func TestStopXrayWaitsForGracefulExit(t *testing.T) {
	tempDir := t.TempDir()
	helper := buildFakeGracefulStopHelper(t, tempDir)
	readyFile := filepath.Join(tempDir, "ready")
	stopFile := filepath.Join(tempDir, "stopped")
	cmd := exec.Command(helper)
	cmd.Env = append(os.Environ(),
		"FAKE_READY_MARKER="+readyFile,
		"FAKE_STOP_MARKER="+stopFile,
		"FAKE_STOP_DELAY_MS=250",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, readyFile)
	active := &activeProcess{
		xrayCmd:  cmd,
		xrayDone: make(chan struct{}),
	}
	go func() {
		_ = cmd.Wait()
		close(active.xrayDone)
	}()
	manager := NewManager(Options{StopTimeout: 25 * time.Millisecond, XrayStopTimeout: time.Second}, Callbacks{})

	started := time.Now()
	manager.stopXray(active)
	elapsed := time.Since(started)

	if elapsed < 200*time.Millisecond {
		t.Fatalf("xray was not allowed to exit gracefully, elapsed=%s", elapsed)
	}
	if _, err := os.Stat(stopFile); err != nil {
		t.Fatalf("expected graceful stop marker: %v", err)
	}
}

func TestCleanupStaleLaunchFilesWaitsBeforeForceKill(t *testing.T) {
	tempDir := t.TempDir()
	helper := buildFakeGracefulStopHelper(t, tempDir)
	readyFile := filepath.Join(tempDir, "ready")
	stopFile := filepath.Join(tempDir, "stopped")
	cmd := exec.Command(helper)
	cmd.Env = append(os.Environ(),
		"FAKE_READY_MARKER="+readyFile,
		"FAKE_STOP_MARKER="+stopFile,
		"FAKE_STOP_DELAY_MS=250",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	waitForFile(t, readyFile)

	pidFile := filepath.Join(tempDir, ".wd-1.xray.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, ".wd-1.xray.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	if err := cleanupStaleLaunchFiles(tempDir, time.Second, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)

	if elapsed < 200*time.Millisecond {
		t.Fatalf("stale cleanup did not wait for graceful exit, elapsed=%s", elapsed)
	}
	if _, err := os.Stat(stopFile); err != nil {
		t.Fatalf("expected stale process to stop gracefully: %v", err)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("expected stale pid file to be removed, err=%v", err)
	}
}

func TestWaitForSystemProxyFailsAndCleanupRestores(t *testing.T) {
	guard := &fakeSystemProxyGuard{verifyErr: errors.New("not applied")}
	manager := NewManager(Options{SystemProxyVerifyTimeout: 20 * time.Millisecond}, Callbacks{})
	active := &activeProcess{systemProxyGuard: guard}

	err := manager.waitForSystemProxy(context.Background(), active, "127.0.0.1", 1080)
	if err == nil || !strings.Contains(err.Error(), "system proxy did not apply") {
		t.Fatalf("expected system proxy verification error, got %v", err)
	}
	manager.cleanup(active)
	if !guard.restored {
		t.Fatal("expected cleanup to restore system proxy guard")
	}
}

func buildFakeMasterDNSHelper(t *testing.T, dir string) string {
	t.Helper()
	source := filepath.Join(dir, "fake_masterdns.go")
	binary := filepath.Join(dir, "fake-masterdns")
	if err := os.WriteFile(source, []byte(fakeMasterDNSSource), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", binary, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fake helper: %v\n%s", err, output)
	}
	return binary
}

func buildFakeXrayHelper(t *testing.T, dir string) string {
	t.Helper()
	source := filepath.Join(dir, "fake_xray.go")
	binary := filepath.Join(dir, "fake-xray")
	if err := os.WriteFile(source, []byte(fakeXraySource), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", binary, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fake xray: %v\n%s", err, output)
	}
	return binary
}

func buildFakeGracefulStopHelper(t *testing.T, dir string) string {
	t.Helper()
	source := filepath.Join(dir, "fake_graceful_stop.go")
	binary := filepath.Join(dir, "fake-graceful-stop")
	if err := os.WriteFile(source, []byte(fakeGracefulStopSource), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", binary, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fake graceful stop helper: %v\n%s", err, output)
	}
	return binary
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

type fakeSystemProxyGuard struct {
	verifyErr error
	restored  bool
}

func (g *fakeSystemProxyGuard) Apply(context.Context) error {
	return nil
}

func (g *fakeSystemProxyGuard) Verify(context.Context) error {
	return g.verifyErr
}

func (g *fakeSystemProxyGuard) Restore(context.Context) error {
	g.restored = true
	return nil
}

func (g *fakeSystemProxyGuard) Snapshot() systemProxySnapshot {
	return systemProxySnapshot{Platform: "linux", Backend: "fake", Values: map[string]string{}}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

type sequenceTrafficSampler struct {
	samples []traffic.Counters
	index   int
}

func (s *sequenceTrafficSampler) Sample(_ context.Context, _ int) (traffic.Counters, error) {
	if len(s.samples) == 0 {
		return traffic.Counters{}, traffic.ErrNoSample
	}
	if s.index >= len(s.samples) {
		return s.samples[len(s.samples)-1], nil
	}
	sample := s.samples[s.index]
	s.index++
	return sample, nil
}

type recoveringTrafficSampler struct {
	calls int
}

func (s *recoveringTrafficSampler) Sample(_ context.Context, _ int) (traffic.Counters, error) {
	s.calls++
	if s.calls == 1 {
		return traffic.Counters{}, errors.New("permission denied")
	}
	return traffic.Counters{RXBytes: int64(1000 + s.calls), TXBytes: int64(500 + s.calls)}, nil
}

const fakeMasterDNSSource = `
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
)

func main() {
	configPath := ""
	for i := 1; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-config" {
			configPath = os.Args[i+1]
		}
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	match := regexp.MustCompile(` + "`" + `LISTEN_PORT\s*=\s*(\d+)` + "`" + `).FindSubmatch(raw)
	if match == nil {
		panic("missing port")
	}
	port, _ := strconv.Atoi(string(match[1]))
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("WD_PROGRESS phase=starting percent=5")
	fmt.Println("WD_RESOLVERS active=1.1.1.1 standby=- valid=1.1.1.1")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
`

const fakeXraySource = `
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
)

func main() {
	configPath := ""
	testOnly := false
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-test" {
			testOnly = true
			continue
		}
		if i >= len(os.Args)-1 {
			continue
		}
		if os.Args[i] == "-c" {
			configPath = os.Args[i+1]
		}
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	listen := "127.0.0.1"
	listenMatch := regexp.MustCompile(` + "`" + `"listen"\s*:\s*"([^"]+)"` + "`" + `).FindSubmatch(raw)
	if listenMatch != nil {
		listen = string(listenMatch[1])
	}
	portMatch := regexp.MustCompile(` + "`" + `"port"\s*:\s*(\d+)` + "`" + `).FindSubmatch(raw)
	if portMatch == nil {
		panic("missing port")
	}
	port, _ := strconv.Atoi(string(portMatch[1]))
	if testOnly {
		fmt.Println("xray config ok")
		return
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(listen, fmt.Sprintf("%d", port)))
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("xray ready")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
`

const fakeGracefulStopSource = `
package main

	import (
		"os"
		"os/signal"
		"strconv"
		"time"
	)

	func main() {
		if ready := os.Getenv("FAKE_READY_MARKER"); ready != "" {
			_ = os.WriteFile(ready, []byte("ready"), 0600)
		}
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt)
		<-stop
		delay, _ := strconv.Atoi(os.Getenv("FAKE_STOP_DELAY_MS"))
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		if marker := os.Getenv("FAKE_STOP_MARKER"); marker != "" {
			_ = os.WriteFile(marker, []byte("stopped"), 0600)
		}
	}
	`

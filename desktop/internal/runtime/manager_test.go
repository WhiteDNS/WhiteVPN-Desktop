package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/traffic"
)

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
	hasXray := active.xrayCmd != nil && active.xrayCmd.Process != nil
	manager.mu.Unlock()
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

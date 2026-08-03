package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/storm"
	"whitevpn-desktop/internal/traffic"
)

type Callbacks struct {
	OnLog           func(string)
	OnState         func(string, string)
	OnProgress      func(model.ConnectionProgress)
	OnResolverState func(model.ResolverRuntimeState)
	OnStats         func(model.TrafficStats)
	OnTrafficStatus func(string)
	OnError         func(string)
}

type Options struct {
	RuntimeDir               string
	MasterDNSSource          string
	BinaryPath               string
	XrayBinaryPath           string
	XrayCoresDir             string
	ClientsDir               string
	EmbeddedClientsFS        fs.FS
	EmbeddedCoresFS          fs.FS
	TrafficSampler           traffic.Sampler
	TrafficInterval          time.Duration
	BuildTimeout             time.Duration
	StartTimeout             time.Duration
	StopTimeout              time.Duration
	XrayStopTimeout          time.Duration
	SystemProxyPlatform      string
	SystemProxyRunner        SystemProxyCommandRunner
	SystemProxyVerifyTimeout time.Duration
}

type XrayLaunchConfig struct {
	ProfileID        string
	Name             string
	XrayConfig       string
	CoreProtocol     string
	SetSystemProxy   bool
	PublicListenIP   string
	PublicListenPort int
	DebugLogs        bool
	TunEnabled       bool
	TunInterfaceName string
	TunMTU           int
	TunIPv6          bool
	TunServerHost    string
}

type Manager struct {
	options   Options
	callbacks Callbacks

	mu     sync.Mutex
	active *activeProcess

	logMu          sync.Mutex
	logWindowStart time.Time
	logWindowCount int
	logDropped     int
}

const (
	targetServerUnavailableMessage = "Target server is overloaded / unavailable."
	fullInitialMTUScanEnv          = "WHITEDNS_FULL_INITIAL_MTU_SCAN"
	skipInitialMTUScanEnv          = "WHITEDNS_SKIP_INITIAL_MTU_SCAN"
	runtimeLogEventsPerSecond      = 60
)

type activeProcess struct {
	id                      string
	debugLogs               bool
	cmd                     *exec.Cmd
	cancel                  context.CancelFunc
	configFile              string
	resolvers               string
	resolversOwned          bool
	mtuScanControlFile      string
	mtuScanPaused           bool
	mtuResolverStateFile    string
	masterPIDFile           string
	xrayCmd                 *exec.Cmd
	xrayCancel              context.CancelFunc
	xrayConfigFile          string
	xrayPIDFile             string
	xrayDone                chan struct{}
	systemProxyGuard        systemProxyGuard
	systemProxySnapshotFile string
	systemProxyRestoreOnce  sync.Once
	tunRouteGuard           tunRouteGuard
	tunRouteSnapshotFile    string
	tunRouteRestoreOnce     sync.Once
	resolverStateCancel     context.CancelFunc
	resolverStateDone       chan struct{}
	resolverStateStopOnce   sync.Once
	resolverStateMu         sync.Mutex
	mtuResolverState        model.ResolverRuntimeState
	hasMTUResolverState     bool
	lastResolverState       model.ResolverRuntimeState
	hasLastResolverState    bool
	trafficStatsMu          sync.Mutex
	logTrafficStatsSeen     bool
	trafficCancel           context.CancelFunc
	trafficDone             chan struct{}
	trafficStopOnce         sync.Once
	stopping                bool
	targetUnavailable       bool
	targetUnavailableAt     time.Time
	targetUnavailableSent   bool
	sessionInitRetries      int
	progressSeen            bool
	lastProgress            model.ConnectionProgress
	progressChangedAt       time.Time
	done                    chan struct{}
	waitErr                 error
}

func NewManager(options Options, callbacks Callbacks) *Manager {
	if options.BuildTimeout == 0 {
		options.BuildTimeout = 2 * time.Minute
	}
	if options.StartTimeout == 0 {
		options.StartTimeout = 45 * time.Second
	}
	if options.StopTimeout == 0 {
		options.StopTimeout = 1500 * time.Millisecond
	}
	if options.XrayStopTimeout == 0 {
		options.XrayStopTimeout = 10 * time.Second
	}
	if options.SystemProxyVerifyTimeout == 0 {
		options.SystemProxyVerifyTimeout = 2 * time.Second
	}
	if options.TrafficInterval == 0 {
		options.TrafficInterval = time.Second
	}
	return &Manager{options: options, callbacks: callbacks}
}

func (m *Manager) RuntimeDir() string {
	if m == nil {
		return ""
	}
	return m.options.RuntimeDir
}

func (m *Manager) Start(ctx context.Context, cfg storm.LaunchConfig) error {
	if err := m.Stop(); err != nil {
		return err
	}
	masterSettings := cfg.MasterDNSSettings
	if masterSettings.ListenPort == 0 {
		masterSettings = cfg.Settings
	}
	debugLogs := masterDNSDebugLogsEnabled(masterSettings)
	publicListenIP := cfg.PublicListenIP
	publicListenPort := cfg.PublicListenPort
	if publicListenPort == 0 {
		publicListenIP = cfg.Settings.ListenIP
		publicListenPort = cfg.Settings.ListenPort
	}
	if strings.TrimSpace(cfg.CoreConfig) == "" {
		return errors.New("xray config is required")
	}
	if err := os.MkdirAll(m.options.RuntimeDir, 0o755); err != nil {
		return err
	}
	m.debugLogf(debugLogs,
		"Debug Desktop MasterDNS start requested: log_level=%s startup_mode=%s full_initial_mtu_scan=%t resolver_lines=%d resolver_path_set=%t listen=%s:%d public=%s:%d mtu_up=%d..%d mtu_down=%d..%d dup=%d/%d strategy=%d workers=%d/%d rx_channel=%d startup_loss=%t/%d/%d/%d recheck=%t/%d",
		masterSettings.LogLevel,
		masterSettings.StartupMode,
		cfg.FullInitialMTUScan,
		countResolverLines(cfg.Resolvers),
		strings.TrimSpace(cfg.ResolversPath) != "",
		masterSettings.ListenIP,
		masterSettings.ListenPort,
		publicListenIP,
		publicListenPort,
		masterSettings.MinUploadMTU,
		masterSettings.MaxUploadMTU,
		masterSettings.MinDownloadMTU,
		masterSettings.MaxDownloadMTU,
		masterSettings.UploadDuplication,
		masterSettings.DownloadDuplication,
		masterSettings.BalancingStrategy,
		masterSettings.RXTXWorkers,
		masterSettings.TunnelProcessWorkers,
		masterSettings.RXChannelSize,
		masterSettings.MTUStartupLossVerifyEnabled,
		masterSettings.MTUStartupLossVerifySamples,
		masterSettings.MTUStartupLossVerifyMaxLossPct,
		masterSettings.MTUStartupLossVerifyCandidates,
		masterSettings.MTURecheckEnabled,
		masterSettings.MTURecheckIntervalMinutes,
	)
	if err := cleanupStaleLaunchFiles(m.options.RuntimeDir, m.options.XrayStopTimeout, m.log, m.options.SystemProxyPlatform, m.options.SystemProxyRunner); err != nil {
		m.log(fmt.Sprintf("Runtime cleanup warning: %v", err))
	}

	binaryPath, err := m.resolveBinary(ctx)
	if err != nil {
		return err
	}
	m.debugLogf(debugLogs, "Debug Desktop resolved MasterDNS helper: path=%s runtime_dir=%s", binaryPath, m.options.RuntimeDir)

	launchID := fmt.Sprintf("%d", time.Now().UnixNano())
	configFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".toml")
	mtuResolverStateFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".mtu-resolvers.log")
	resolversFile := strings.TrimSpace(cfg.ResolversPath)
	resolversOwned := false
	if resolversFile == "" {
		resolversFile = filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".resolvers")
		resolversOwned = true
	} else if info, err := os.Stat(resolversFile); err != nil || info.IsDir() {
		return fmt.Errorf("resolver file is unavailable: %s", resolversFile)
	}
	mtuScanControlFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".mtu-scan-control")
	clientTOML := storm.RenderRuntimeClientTOML(cfg.Connection, masterSettings, mtuResolverStateFile)
	if err := os.WriteFile(configFile, []byte(clientTOML), 0o600); err != nil {
		return err
	}
	if resolversOwned {
		if err := os.WriteFile(resolversFile, []byte(cfg.Resolvers), 0o600); err != nil {
			_ = os.Remove(configFile)
			return err
		}
	}
	if err := os.WriteFile(mtuScanControlFile, []byte("resume\n"), 0o600); err != nil {
		_ = os.Remove(configFile)
		if resolversOwned {
			_ = os.Remove(resolversFile)
		}
		return err
	}
	m.debugLogf(debugLogs,
		"Debug Desktop wrote MasterDNS runtime files: config=%s resolvers=%s resolvers_owned=%t mtu_state=%s mtu_control=%s config_bytes=%d",
		configFile,
		resolversFile,
		resolversOwned,
		mtuResolverStateFile,
		mtuScanControlFile,
		len(clientTOML),
	)

	procCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, binaryPath, "-config", configFile, "-resolvers", resolversFile)
	hideConsoleWindow(cmd)
	cmd.Dir = m.options.RuntimeDir
	launchEnv := masterDNSLaunchEnv(cfg, mtuScanControlFile)
	cmd.Env = append(os.Environ(), launchEnv...)
	m.debugLogf(debugLogs, "Debug Desktop MasterDNS launch env: %s", strings.Join(launchEnv, ","))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = os.Remove(configFile)
		if resolversOwned {
			_ = os.Remove(resolversFile)
		}
		_ = os.Remove(mtuScanControlFile)
		return err
	}
	cmd.Stderr = cmd.Stdout

	m.state(model.RuntimeConnecting, "Starting MasterDNS")
	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(configFile)
		if resolversOwned {
			_ = os.Remove(resolversFile)
		}
		_ = os.Remove(mtuScanControlFile)
		return err
	}
	masterPIDFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".masterdns.pid")
	if err := writePIDFile(masterPIDFile, cmd.Process.Pid); err != nil {
		m.log(fmt.Sprintf("Runtime cleanup warning: failed to write MasterDNS pid file: %v", err))
	}
	m.debugLogf(debugLogs, "Debug Desktop MasterDNS process started: pid=%d pid_file=%s", cmd.Process.Pid, masterPIDFile)

	active := &activeProcess{
		id:                   launchID,
		debugLogs:            debugLogs,
		cmd:                  cmd,
		cancel:               cancel,
		configFile:           configFile,
		resolvers:            resolversFile,
		resolversOwned:       resolversOwned,
		mtuScanControlFile:   mtuScanControlFile,
		mtuResolverStateFile: mtuResolverStateFile,
		masterPIDFile:        masterPIDFile,
		done:                 make(chan struct{}),
	}
	m.mu.Lock()
	m.active = active
	m.mu.Unlock()

	m.startTrafficMonitor(active, cmd.Process.Pid)
	m.startMTUResolverStateMonitor(active)
	go m.drainOutput(active, stdout)
	go m.waitForExit(active)

	if err := m.waitForPort(ctx, masterSettings.ListenIP, masterSettings.ListenPort, active); err != nil {
		_ = m.Stop()
		return stormDNSReadinessError(err)
	}
	m.debugLogf(debugLogs, "Debug Desktop MasterDNS local port is ready: %s:%d", masterSettings.ListenIP, masterSettings.ListenPort)
	if err := m.startXray(ctx, cfg, active); err != nil {
		_ = m.Stop()
		return err
	}
	if err := m.waitForPort(ctx, publicListenIP, publicListenPort, active); err != nil {
		_ = m.Stop()
		return err
	}
	if err := m.waitForSystemProxy(ctx, active, publicListenIP, publicListenPort); err != nil {
		_ = m.Stop()
		return err
	}
	m.debugLogf(debugLogs, "Debug Desktop public proxy port is ready: %s:%d", publicListenIP, publicListenPort)
	m.state(model.RuntimeConnected, "Proxy is connected")
	return nil
}

func (m *Manager) StartXray(ctx context.Context, cfg XrayLaunchConfig) error {
	if err := m.Stop(); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.XrayConfig) == "" {
		return errors.New("xray config is required")
	}
	if cfg.PublicListenPort <= 0 {
		return errors.New("V2Ray local proxy port is required")
	}
	if err := os.MkdirAll(m.options.RuntimeDir, 0o755); err != nil {
		return err
	}
	if err := cleanupStaleLaunchFiles(m.options.RuntimeDir, m.options.XrayStopTimeout, m.log, m.options.SystemProxyPlatform, m.options.SystemProxyRunner); err != nil {
		m.log(fmt.Sprintf("Runtime cleanup warning: %v", err))
	}

	binaryPath, err := m.resolveXrayBinary(ctx)
	if err != nil {
		return err
	}
	launchID := fmt.Sprintf("%d", time.Now().UnixNano())
	configFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".xray.json")
	if err := os.WriteFile(configFile, []byte(cfg.XrayConfig), 0o600); err != nil {
		return err
	}
	m.log(fmt.Sprintf("V2Ray xray config written: path=%s bytes=%d", configFile, len(cfg.XrayConfig)))
	m.debugLogf(cfg.DebugLogs, "Debug Desktop wrote V2Ray xray config: path=%s bytes=%d", configFile, len(cfg.XrayConfig))
	if cfg.TunEnabled {
		m.log("V2Ray TUN mode enabled; skipping xray config preflight because native TUN validation creates an OS interface")
	} else if err := m.testXrayConfig(ctx, binaryPath, configFile); err != nil {
		_ = os.Remove(configFile)
		return err
	}

	tunRouteGuard, err := m.prepareTunRouteGuard(ctx, cfg, binaryPath)
	if err != nil {
		_ = os.Remove(configFile)
		return err
	}
	tunRouteSnapshotFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".tun-routes.json")
	if err := writeTunRouteSnapshotFile(tunRouteSnapshotFile, tunRouteGuard); err != nil {
		_ = os.Remove(configFile)
		return err
	}

	systemProxyEnabled := cfg.SetSystemProxy && !cfg.TunEnabled
	if cfg.SetSystemProxy && cfg.TunEnabled {
		m.log("System proxy skipped because V2Ray TUN mode is enabled")
	}
	systemProxyGuard, err := m.prepareSystemProxyGuard(ctx, systemProxyEnabled, cfg.CoreProtocol, cfg.PublicListenIP, cfg.PublicListenPort)
	if err != nil {
		restoreTunRouteGuardWithLog(tunRouteGuard, m.log)
		_ = os.Remove(tunRouteSnapshotFile)
		_ = os.Remove(configFile)
		return err
	}
	systemProxySnapshotFile := filepath.Join(m.options.RuntimeDir, ".wd-"+launchID+".system-proxy.json")
	if err := writeSystemProxySnapshotFile(systemProxySnapshotFile, systemProxyGuard); err != nil {
		restoreSystemProxyGuardWithLog(systemProxyGuard, m.log)
		restoreTunRouteGuardWithLog(tunRouteGuard, m.log)
		_ = os.Remove(tunRouteSnapshotFile)
		_ = os.Remove(configFile)
		return err
	}
	procCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, binaryPath, "run", "-c", configFile)
	hideConsoleWindow(cmd)
	cmd.Dir = m.options.RuntimeDir
	cmd.Env = xrayProcessEnv(binaryPath, m.xraySearchDirs())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		restoreSystemProxyGuardWithLog(systemProxyGuard, m.log)
		restoreTunRouteGuardWithLog(tunRouteGuard, m.log)
		_ = os.Remove(systemProxySnapshotFile)
		_ = os.Remove(tunRouteSnapshotFile)
		_ = os.Remove(configFile)
		return err
	}
	cmd.Stderr = cmd.Stdout

	active := &activeProcess{
		id:                      launchID,
		debugLogs:               cfg.DebugLogs,
		cancel:                  cancel,
		xrayCmd:                 cmd,
		xrayCancel:              cancel,
		xrayConfigFile:          configFile,
		xrayDone:                make(chan struct{}),
		systemProxyGuard:        systemProxyGuard,
		systemProxySnapshotFile: systemProxySnapshotFile,
		tunRouteGuard:           tunRouteGuard,
		tunRouteSnapshotFile:    tunRouteSnapshotFile,
		done:                    make(chan struct{}),
	}
	m.mu.Lock()
	m.active = active
	m.mu.Unlock()

	m.state(model.RuntimeConnecting, "Starting proxy")
	if err := cmd.Start(); err != nil {
		cancel()
		m.restoreSystemProxyGuard(active)
		m.restoreTunRouteGuard(active)
		_ = os.Remove(systemProxySnapshotFile)
		_ = os.Remove(tunRouteSnapshotFile)
		m.mu.Lock()
		if m.active == active {
			m.active = nil
		}
		m.mu.Unlock()
		_ = os.Remove(configFile)
		return fmt.Errorf("failed to start xray: %w", err)
	}
	pidFile := filepath.Join(m.options.RuntimeDir, ".wd-"+active.id+".xray.pid")
	if err := writePIDFile(pidFile, cmd.Process.Pid); err != nil {
		m.log(fmt.Sprintf("Runtime cleanup warning: failed to write xray pid file: %v", err))
	}
	active.xrayPIDFile = pidFile
	m.log(fmt.Sprintf("V2Ray xray process started: pid=%d listen=%s:%d", cmd.Process.Pid, cfg.PublicListenIP, cfg.PublicListenPort))
	m.debugLogf(cfg.DebugLogs, "Debug Desktop V2Ray xray process started: pid=%d pid_file=%s", cmd.Process.Pid, pidFile)

	m.startTrafficMonitor(active, cmd.Process.Pid)
	go m.drainOutput(active, stdout)
	go m.waitForXrayExit(active)

	if err := m.waitForPort(ctx, cfg.PublicListenIP, cfg.PublicListenPort, active); err != nil {
		_ = m.Stop()
		return err
	}
	if err := m.applyTunRouteGuard(ctx, active); err != nil {
		_ = m.Stop()
		return err
	}
	if err := m.waitForSystemProxy(ctx, active, cfg.PublicListenIP, cfg.PublicListenPort); err != nil {
		_ = m.Stop()
		return err
	}
	m.log(fmt.Sprintf("V2Ray local proxy port is ready: %s:%d", cfg.PublicListenIP, cfg.PublicListenPort))
	m.debugLogf(cfg.DebugLogs, "Debug Desktop V2Ray public proxy port is ready: %s:%d", cfg.PublicListenIP, cfg.PublicListenPort)
	m.state(model.RuntimeConnected, "Proxy is connected")
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	active := m.active
	if active == nil {
		m.mu.Unlock()
		return nil
	}
	active.stopping = true
	m.active = nil
	m.mu.Unlock()

	m.stopXray(active)
	m.stopMasterDNS(active)
	if active.cancel != nil {
		active.cancel()
	}
	m.cleanup(active)
	m.state(model.RuntimeDisconnected, "Disconnected")
	return nil
}

func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return false
	}
	return (m.active.cmd != nil && m.active.cmd.Process != nil) ||
		(m.active.xrayCmd != nil && m.active.xrayCmd.Process != nil)
}

func (m *Manager) SetResolverMTUScanPaused(paused bool) error {
	m.mu.Lock()
	active := m.active
	if active == nil || active.stopping {
		m.mu.Unlock()
		return errors.New("runtime is not running")
	}
	controlFile := active.mtuScanControlFile
	m.mu.Unlock()
	if strings.TrimSpace(controlFile) == "" {
		return errors.New("resolver MTU scan control is unavailable")
	}

	value := "resume\n"
	label := "resumed"
	if paused {
		value = "pause\n"
		label = "paused"
	}
	if err := os.WriteFile(controlFile, []byte(value), 0o600); err != nil {
		return err
	}

	m.mu.Lock()
	if m.active == active {
		active.mtuScanPaused = paused
	}
	m.mu.Unlock()
	m.log("Resolver MTU scanning " + label)
	return nil
}

func masterDNSLaunchEnv(cfg storm.LaunchConfig, mtuScanControlFile string) []string {
	env := []string{"WHITEDNS_MTU_SCAN_CONTROL_FILE=" + mtuScanControlFile}
	if cfg.FullInitialMTUScan {
		env = append(env, fullInitialMTUScanEnv+"=1")
	}
	if cfg.SkipInitialMTUScan {
		env = append(env, skipInitialMTUScanEnv+"=1")
	}
	return env
}

func (m *Manager) ResolveClientBinary(ctx context.Context) (string, error) {
	return m.resolveBinary(ctx)
}

func (m *Manager) resolveBinary(ctx context.Context) (string, error) {
	if m.options.BinaryPath != "" {
		if isExecutableFile(m.options.BinaryPath) {
			return m.options.BinaryPath, nil
		}
		return "", fmt.Errorf("MasterDNS helper not found: %s", m.options.BinaryPath)
	}

	name := helperPlatformName()
	checkedDirs := make([]string, 0)
	for _, dir := range m.clientSearchDirs() {
		checkedDirs = appendUnique(checkedDirs, dir)
		if candidate, ok := findClientBinaryInDir(dir); ok {
			return candidate, nil
		}
	}
	for _, base := range candidateBases() {
		for _, dirName := range []string{"clients", "bin"} {
			dir := filepath.Join(base, dirName)
			checkedDirs = appendUnique(checkedDirs, dir)
			if candidate, ok := findClientBinaryInDir(dir); ok {
				return candidate, nil
			}
		}
	}
	if candidate, ok := m.extractEmbeddedClient(name); ok {
		return candidate, nil
	}

	sourceDir := strings.TrimSpace(m.options.MasterDNSSource)
	if sourceDir == "" {
		return "", fmt.Errorf(
			"MasterDNS client helper not found; expected %s in a clients/ folder. Checked: %s",
			name,
			strings.Join(checkedDirs, ", "),
		)
	}
	out := filepath.Join(m.options.RuntimeDir, "helper", name)
	if isExecutableFile(out) {
		return out, nil
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}

	buildCtx, cancel := context.WithTimeout(ctx, m.options.BuildTimeout)
	defer cancel()
	m.log("Building MasterDNS helper from source")
	cmd := exec.CommandContext(buildCtx, "go", "build", "-o", out, "./cmd/client")
	hideConsoleWindow(cmd)
	cmd.Dir = sourceDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to build MasterDNS helper: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return out, nil
}

func (m *Manager) clientSearchDirs() []string {
	dirs := make([]string, 0)
	if envDir := strings.TrimSpace(os.Getenv("WHITEDNS_CLIENTS_DIR")); envDir != "" {
		dirs = append(dirs, envDir)
	}
	if strings.TrimSpace(m.options.ClientsDir) == "" {
		if m.options.RuntimeDir != "" {
			dirs = append(dirs, filepath.Join(filepath.Dir(m.options.RuntimeDir), "clients"))
		}
		return dirs
	}
	dirs = append(dirs, m.options.ClientsDir)
	if m.options.RuntimeDir != "" {
		dirs = append(dirs, filepath.Join(filepath.Dir(m.options.RuntimeDir), "clients"))
	}
	return dirs
}

func (m *Manager) extractEmbeddedClient(name string) (string, bool) {
	if m.options.EmbeddedClientsFS == nil || m.options.RuntimeDir == "" {
		return "", false
	}
	for _, candidateName := range helperNameCandidates() {
		raw, err := fs.ReadFile(m.options.EmbeddedClientsFS, filepath.ToSlash(filepath.Join("clients", candidateName)))
		if err != nil || len(raw) == 0 {
			continue
		}
		out := filepath.Join(m.options.RuntimeDir, "helper", name)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return "", false
		}
		if err := os.WriteFile(out, raw, 0o755); err != nil {
			return "", false
		}
		if isExecutableFile(out) {
			return out, true
		}
	}
	return "", false
}

func (m *Manager) extractEmbeddedXray(name string) (string, bool) {
	if m.options.EmbeddedCoresFS == nil || m.options.RuntimeDir == "" {
		return "", false
	}
	for _, candidateName := range xrayNameCandidates() {
		raw, err := fs.ReadFile(m.options.EmbeddedCoresFS, filepath.ToSlash(filepath.Join("cores", candidateName)))
		if err != nil || len(raw) == 0 {
			continue
		}
		out := filepath.Join(m.options.RuntimeDir, "helper", name)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return "", false
		}
		if err := os.WriteFile(out, raw, 0o755); err != nil {
			return "", false
		}
		for _, assetName := range []string{"geoip.dat", "geosite.dat"} {
			assetRaw, err := fs.ReadFile(m.options.EmbeddedCoresFS, filepath.ToSlash(filepath.Join("cores", assetName)))
			if err == nil && len(assetRaw) > 0 {
				_ = os.WriteFile(filepath.Join(filepath.Dir(out), assetName), assetRaw, 0o644)
			}
		}
		if goruntime.GOOS == "windows" {
			assetRaw, err := fs.ReadFile(m.options.EmbeddedCoresFS, filepath.ToSlash(filepath.Join("cores", "wintun.dll")))
			if err == nil && len(assetRaw) > 0 {
				_ = os.WriteFile(filepath.Join(filepath.Dir(out), "wintun.dll"), assetRaw, 0o755)
			}
		}
		if isExecutableFile(out) {
			return out, true
		}
	}
	return "", false
}

func (m *Manager) startXray(ctx context.Context, cfg storm.LaunchConfig, active *activeProcess) error {
	binaryPath, err := m.resolveXrayBinary(ctx)
	if err != nil {
		return err
	}
	m.debugLogf(active.debugLogs, "Debug Desktop resolved xray helper: path=%s", binaryPath)
	configFile := filepath.Join(m.options.RuntimeDir, ".wd-"+active.id+".xray.json")
	if err := os.WriteFile(configFile, []byte(cfg.CoreConfig), 0o600); err != nil {
		return err
	}
	m.debugLogf(active.debugLogs, "Debug Desktop wrote xray config: path=%s bytes=%d", configFile, len(cfg.CoreConfig))
	if err := m.testXrayConfig(ctx, binaryPath, configFile); err != nil {
		_ = os.Remove(configFile)
		return err
	}

	systemProxyGuard, err := m.prepareSystemProxyGuard(ctx, cfg.SetSystemProxy, cfg.CoreProtocol, cfg.PublicListenIP, cfg.PublicListenPort)
	if err != nil {
		_ = os.Remove(configFile)
		return err
	}
	systemProxySnapshotFile := filepath.Join(m.options.RuntimeDir, ".wd-"+active.id+".system-proxy.json")
	if err := writeSystemProxySnapshotFile(systemProxySnapshotFile, systemProxyGuard); err != nil {
		restoreSystemProxyGuardWithLog(systemProxyGuard, m.log)
		_ = os.Remove(configFile)
		return err
	}
	procCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, binaryPath, "run", "-c", configFile)
	hideConsoleWindow(cmd)
	cmd.Dir = m.options.RuntimeDir
	cmd.Env = xrayProcessEnv(binaryPath, m.xraySearchDirs())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		restoreSystemProxyGuardWithLog(systemProxyGuard, m.log)
		_ = os.Remove(systemProxySnapshotFile)
		_ = os.Remove(configFile)
		return err
	}
	cmd.Stderr = cmd.Stdout

	m.state(model.RuntimeConnecting, "Starting xray proxy")
	if err := cmd.Start(); err != nil {
		cancel()
		restoreSystemProxyGuardWithLog(systemProxyGuard, m.log)
		_ = os.Remove(systemProxySnapshotFile)
		_ = os.Remove(configFile)
		return fmt.Errorf("failed to start xray: %w", err)
	}
	pidFile := filepath.Join(m.options.RuntimeDir, ".wd-"+active.id+".xray.pid")
	if err := writePIDFile(pidFile, cmd.Process.Pid); err != nil {
		m.log(fmt.Sprintf("Runtime cleanup warning: failed to write xray pid file: %v", err))
	}
	m.debugLogf(active.debugLogs, "Debug Desktop xray process started: pid=%d pid_file=%s", cmd.Process.Pid, pidFile)

	active.xrayCmd = cmd
	active.xrayCancel = cancel
	active.xrayConfigFile = configFile
	active.xrayPIDFile = pidFile
	active.xrayDone = make(chan struct{})
	active.systemProxyGuard = systemProxyGuard
	active.systemProxySnapshotFile = systemProxySnapshotFile
	go m.drainOutput(active, stdout)
	go m.waitForXrayExit(active)
	return nil
}

func (m *Manager) testXrayConfig(ctx context.Context, binaryPath string, configFile string) error {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(testCtx, binaryPath, "run", "-test", "-c", configFile)
	hideConsoleWindow(cmd)
	cmd.Dir = m.options.RuntimeDir
	cmd.Env = xrayProcessEnv(binaryPath, m.xraySearchDirs())
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	return fmt.Errorf("xray config validation failed: %s", message)
}

func (m *Manager) resolveXrayBinary(ctx context.Context) (string, error) {
	_ = ctx
	if m.options.XrayBinaryPath != "" {
		if isExecutableFile(m.options.XrayBinaryPath) {
			return m.options.XrayBinaryPath, nil
		}
		return "", fmt.Errorf("xray core not found: %s", m.options.XrayBinaryPath)
	}
	if envPath := strings.TrimSpace(os.Getenv("WHITEDNS_XRAY_BIN")); envPath != "" {
		if isExecutableFile(envPath) {
			return envPath, nil
		}
		return "", fmt.Errorf("xray core not found: %s", envPath)
	}
	if envPath := strings.TrimSpace(os.Getenv("XRAY_BIN")); envPath != "" {
		if isExecutableFile(envPath) {
			return envPath, nil
		}
		return "", fmt.Errorf("xray core not found: %s", envPath)
	}

	checkedDirs := make([]string, 0)
	for _, dir := range m.xraySearchDirs() {
		checkedDirs = appendUnique(checkedDirs, dir)
		if candidate, ok := findXrayBinaryInDir(dir); ok {
			return candidate, nil
		}
	}
	if candidate, ok := m.extractEmbeddedXray(xrayPlatformName()); ok {
		return candidate, nil
	}
	if path, err := exec.LookPath("xray"); err == nil && isExecutableFile(path) {
		return path, nil
	}
	return "", fmt.Errorf(
		"xray core not found; install xray or place %s in a cores/ folder. Checked: %s",
		xrayPlatformName(),
		strings.Join(checkedDirs, ", "),
	)
}

func (m *Manager) xraySearchDirs() []string {
	dirs := make([]string, 0)
	if envDir := strings.TrimSpace(os.Getenv("WHITEDNS_XRAY_DIR")); envDir != "" {
		dirs = append(dirs, envDir)
	}
	if strings.TrimSpace(m.options.XrayCoresDir) != "" {
		dirs = append(dirs, m.options.XrayCoresDir)
	}
	if strings.TrimSpace(m.options.ClientsDir) != "" {
		dirs = append(dirs, filepath.Join(filepath.Dir(m.options.ClientsDir), "cores"))
	}
	if m.options.RuntimeDir != "" {
		dirs = append(dirs, filepath.Join(filepath.Dir(m.options.RuntimeDir), "cores"))
	}
	for _, base := range candidateBases() {
		dirs = append(dirs, filepath.Join(base, "cores"), filepath.Join(base, "bin"))
	}
	return dirs
}

func xrayProcessEnv(binaryPath string, searchDirs []string) []string {
	env := os.Environ()
	if assetDir := xrayAssetDir(binaryPath, searchDirs); assetDir != "" {
		env = append(env, "XRAY_LOCATION_ASSET="+assetDir)
	}
	return env
}

func xrayAssetDir(binaryPath string, searchDirs []string) string {
	if envDir := strings.TrimSpace(os.Getenv("WHITEDNS_XRAY_ASSET_DIR")); hasXrayGeodata(envDir) {
		return envDir
	}
	if hasXrayGeodata(filepath.Dir(binaryPath)) {
		return filepath.Dir(binaryPath)
	}
	for _, dir := range searchDirs {
		if hasXrayGeodata(dir) {
			return dir
		}
	}
	return ""
}

func hasXrayGeodata(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "geoip.dat")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err != nil {
		return false
	}
	return true
}

func (m *Manager) waitForPort(ctx context.Context, host string, port int, active *activeProcess) error {
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	m.debugLogf(active.debugLogs, "Debug Desktop waiting for local port: address=%s", address)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			running, stopping := m.readinessProcessState(active)
			if !running {
				if stopping {
					return context.Canceled
				}
				return errors.New("runtime exited before proxy port became ready")
			}
			conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				m.debugLogf(active.debugLogs, "Debug Desktop local port opened: address=%s", address)
				return nil
			}
			if m.startupReadinessFailed(active) {
				return fmt.Errorf("proxy port did not open at %s", address)
			}
		}
	}
}

func (m *Manager) startupReadinessFailed(active *activeProcess) bool {
	var lastProgress model.ConnectionProgress
	progressSeen := false
	targetUnavailable := false
	var targetUnavailableAt time.Time
	var progressChangedAt time.Time
	m.mu.Lock()
	if m.active == active {
		progressSeen = active.progressSeen
		lastProgress = active.lastProgress
		targetUnavailable = active.targetUnavailable
		targetUnavailableAt = active.targetUnavailableAt
		progressChangedAt = active.progressChangedAt
	}
	m.mu.Unlock()

	if !targetUnavailable {
		return false
	}
	if !progressSeen || (!startupMTUScanInProgress(lastProgress) && !startupSessionInitInProgress(lastProgress)) {
		return true
	}
	return startupReadinessStalled(time.Now(), targetUnavailableAt, progressChangedAt, m.options.StartTimeout)
}

func startupMTUScanInProgress(progress model.ConnectionProgress) bool {
	return progress.Phase == "mtu" && progress.Total > 0 && progress.Completed < progress.Total
}

func startupSessionInitInProgress(progress model.ConnectionProgress) bool {
	return progress.Phase == "session"
}

func startupReadinessStalled(now time.Time, targetUnavailableAt time.Time, progressChangedAt time.Time, grace time.Duration) bool {
	if grace <= 0 {
		return true
	}
	since := laterTime(targetUnavailableAt, progressChangedAt)
	if since.IsZero() {
		return true
	}
	return !now.Before(since.Add(grace))
}

func laterTime(first time.Time, second time.Time) time.Time {
	if first.IsZero() || second.After(first) {
		return second
	}
	return first
}

func (m *Manager) readinessProcessState(active *activeProcess) (running bool, stopping bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == active && !active.stopping {
		return true, false
	}
	return false, active != nil && active.stopping
}

func stormDNSReadinessError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	if strings.Contains(err.Error(), "proxy port did not open") {
		return errors.New(targetServerUnavailableMessage)
	}
	return err
}

func (m *Manager) drainOutput(active *activeProcess, stdout any) {
	reader, ok := stdout.(interface {
		Read([]byte) (int, error)
	})
	if !ok {
		return
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := storm.CleanLogLine(scanner.Text())
		if line == "" {
			continue
		}
		if progress, ok := storm.ParseProgress(line); ok {
			m.debugLogf(active.debugLogs,
				"Debug Desktop parsed MasterDNS progress: phase=%s percent=%d completed=%d total=%d valid=%d rejected=%d",
				progress.Phase,
				progress.Percent,
				progress.Completed,
				progress.Total,
				progress.Valid,
				progress.Rejected,
			)
			m.recordProgress(active, progress)
			m.progress(progress)
		}
		if resolvers, ok := storm.ParseResolverState(line); ok {
			m.debugLogf(active.debugLogs,
				"Debug Desktop parsed MasterDNS resolver state: total=%d active=%d valid=%d rejected=%d pending=%d active_complete=%t valid_complete=%t details=%d",
				resolvers.TotalCount,
				resolvers.ActiveCount,
				resolvers.ValidCount,
				resolvers.RejectedCount,
				resolvers.PendingCount,
				resolvers.ActiveComplete,
				resolvers.ValidComplete,
				len(resolvers.ResolverDetails),
			)
			m.recordResolverState(active, resolvers)
		}
		if stats, ok := storm.ParseTrafficStats(line); ok {
			m.recordLogTrafficStats(active, stats)
			continue
		}
		if storm.IsSessionInitAttemptLog(line) {
			if progress, ok := m.recordSessionInitProgress(active, false); ok {
				m.progress(progress)
				m.state(model.RuntimeConnecting, "Initializing session")
			}
		}
		if storm.IsSessionInitRetryLog(line) {
			if progress, ok := m.recordSessionInitProgress(active, true); ok {
				m.progress(progress)
				m.state(model.RuntimeConnecting, "Session init retrying...")
				m.markTargetUnavailable(active, false)
			}
		}
		if storm.IsTargetServerUnavailableLog(line) {
			m.notifyTargetUnavailable(active)
		}
		if storm.IsBenignLocalProxyAbortLog(line) {
			continue
		}
		m.log(line)
	}
}

func (m *Manager) startMTUResolverStateMonitor(active *activeProcess) {
	if strings.TrimSpace(active.mtuResolverStateFile) == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	active.resolverStateCancel = cancel
	active.resolverStateDone = make(chan struct{})
	go m.watchMTUResolverStateFile(ctx, active)
}

func (m *Manager) watchMTUResolverStateFile(ctx context.Context, active *activeProcess) {
	defer close(active.resolverStateDone)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var lastRaw string

	read := func() bool {
		raw, err := os.ReadFile(active.mtuResolverStateFile)
		if err != nil {
			if os.IsNotExist(err) {
				return true
			}
			if m.isActive(active) {
				m.log(fmt.Sprintf("Resolver state file warning: %v", err))
			}
			return true
		}
		rawText := string(raw)
		if rawText == lastRaw {
			return true
		}
		lastRaw = rawText
		state, ok := storm.ParseMTUResolverRuntimeState(rawText)
		if !ok {
			return true
		}
		m.debugLogf(active.debugLogs,
			"Debug Desktop parsed MasterDNS MTU state file: active=%d valid=%d details=%d bytes=%d",
			state.ActiveCount,
			state.ValidCount,
			len(state.ResolverDetails),
			len(raw),
		)
		m.updateMTUResolverState(active, state)
		return true
	}

	if !read() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !read() {
				return
			}
		}
	}
}

func (m *Manager) updateMTUResolverState(active *activeProcess, state model.ResolverRuntimeState) {
	active.resolverStateMu.Lock()
	if active.hasMTUResolverState && resolverRuntimeStateEqual(active.mtuResolverState, state) {
		active.resolverStateMu.Unlock()
		return
	}
	active.mtuResolverState = state
	active.hasMTUResolverState = true
	emitState := state
	if active.hasLastResolverState {
		emitState = mergeResolverRuntimeState(active.lastResolverState, state)
	}
	active.resolverStateMu.Unlock()
	if m.isActive(active) {
		m.debugLogf(active.debugLogs,
			"Debug Desktop emitting merged resolver state from MTU file: active=%d valid=%d details=%d",
			emitState.ActiveCount,
			emitState.ValidCount,
			len(emitState.ResolverDetails),
		)
		m.resolverState(emitState)
	}
}

func (m *Manager) recordResolverState(active *activeProcess, state model.ResolverRuntimeState) {
	active.resolverStateMu.Lock()
	active.lastResolverState = state
	active.hasLastResolverState = true
	if !resolverRuntimeStateComplete(state) {
		fileState := active.mtuResolverState
		hasFileState := active.hasMTUResolverState
		if hasFileState {
			state = mergeResolverRuntimeState(state, fileState)
		}
	}
	active.resolverStateMu.Unlock()
	m.debugLogf(active.debugLogs,
		"Debug Desktop emitting resolver state from MasterDNS log: active=%d valid=%d rejected=%d pending=%d details=%d",
		state.ActiveCount,
		state.ValidCount,
		state.RejectedCount,
		state.PendingCount,
		len(state.ResolverDetails),
	)
	m.resolverState(state)
}

func (m *Manager) startTrafficMonitor(active *activeProcess, pid int) {
	sampler := m.options.TrafficSampler
	if sampler == nil {
		sampler = traffic.DefaultSampler()
	}
	if sampler == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	active.trafficCancel = cancel
	active.trafficDone = make(chan struct{})
	go m.watchTraffic(ctx, active, pid, sampler)
}

func (m *Manager) watchTraffic(ctx context.Context, active *activeProcess, pid int, sampler traffic.Sampler) {
	defer close(active.trafficDone)
	var meter traffic.Meter
	ticker := time.NewTicker(m.options.TrafficInterval)
	defer ticker.Stop()

	sample := func() bool {
		counters, err := sampler.Sample(ctx, pid)
		if err != nil {
			if errors.Is(err, traffic.ErrNoSample) || errors.Is(err, context.Canceled) {
				return true
			}
			if m.isActive(active) && !active.hasLogTrafficStats() {
				m.trafficStatus(err.Error())
			}
			return true
		}
		if !m.isActive(active) {
			return false
		}
		if active.hasLogTrafficStats() {
			m.trafficStatus("")
			return true
		}
		m.trafficStatus("")
		usage := meter.Observe(counters, time.Now())
		m.stats(model.TrafficStats{
			DownloadBytes:               usage.RXBytes,
			UploadBytes:                 usage.TXBytes,
			DownloadSpeedBytesPerSecond: usage.RXBytesPerSecond,
			UploadSpeedBytesPerSecond:   usage.TXBytesPerSecond,
			TotalDataUsageBytes:         usage.TotalBytes,
		})
		return true
	}

	if !sample() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !sample() {
				return
			}
		}
	}
}

func (m *Manager) recordLogTrafficStats(active *activeProcess, stats model.TrafficStats) {
	if active != nil {
		active.trafficStatsMu.Lock()
		active.logTrafficStatsSeen = true
		active.trafficStatsMu.Unlock()
	}
	m.stats(stats)
}

func (active *activeProcess) hasLogTrafficStats() bool {
	if active == nil {
		return false
	}
	active.trafficStatsMu.Lock()
	defer active.trafficStatsMu.Unlock()
	return active.logTrafficStatsSeen
}

func (m *Manager) recordProgress(active *activeProcess, progress model.ConnectionProgress) {
	now := time.Now()
	m.mu.Lock()
	if m.active == active {
		if !active.progressSeen || connectionProgressChanged(active.lastProgress, progress) {
			active.progressChangedAt = now
		}
		active.progressSeen = true
		active.lastProgress = progress
	}
	m.mu.Unlock()
}

func (m *Manager) recordSessionInitProgress(active *activeProcess, retry bool) (model.ConnectionProgress, bool) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != active {
		return model.ConnectionProgress{}, false
	}
	if retry {
		active.sessionInitRetries++
	}
	progress := model.ConnectionProgress{
		Phase:     "session",
		Percent:   90,
		Completed: active.sessionInitRetries,
	}
	if !active.progressSeen || connectionProgressChanged(active.lastProgress, progress) {
		active.progressChangedAt = now
	}
	active.progressSeen = true
	active.lastProgress = progress
	return progress, true
}

func connectionProgressChanged(previous model.ConnectionProgress, next model.ConnectionProgress) bool {
	return previous.Phase != next.Phase ||
		previous.Percent != next.Percent ||
		previous.Completed != next.Completed ||
		previous.Total != next.Total ||
		previous.Valid != next.Valid ||
		previous.Rejected != next.Rejected
}

func resolverRuntimeStateComplete(state model.ResolverRuntimeState) bool {
	return state.ActiveComplete &&
		state.ValidComplete &&
		len(state.ActiveResolvers) == state.ActiveCount &&
		len(state.ValidResolvers) == state.ValidCount
}

func mergeResolverRuntimeState(logState model.ResolverRuntimeState, fileState model.ResolverRuntimeState) model.ResolverRuntimeState {
	merged := logState
	if len(fileState.ResolverDetails) > 0 {
		merged.ResolverDetails = append([]model.ResolverRuntimeDetail(nil), fileState.ResolverDetails...)
	}
	if len(fileState.ActiveResolvers) > 0 || fileState.ActiveCount > 0 {
		merged.ActiveResolvers = append([]string(nil), fileState.ActiveResolvers...)
		merged.ActiveCount = fileState.ActiveCount
		merged.ActiveComplete = fileState.ActiveComplete
	}
	if len(fileState.ValidResolvers) > 0 || fileState.ValidCount > 0 {
		merged.ValidResolvers = append([]string(nil), fileState.ValidResolvers...)
		merged.ValidCount = fileState.ValidCount
		merged.ValidComplete = fileState.ValidComplete
	}
	if merged.TotalCount < fileState.ValidCount {
		merged.TotalCount = fileState.ValidCount
	}
	if len(merged.StandbyResolvers) == 0 && len(fileState.StandbyResolvers) > 0 {
		merged.StandbyResolvers = append([]string(nil), fileState.StandbyResolvers...)
		merged.StandbyCount = fileState.StandbyCount
		merged.StandbyComplete = fileState.StandbyComplete
	}
	return merged
}

func resolverRuntimeStateEqual(a, b model.ResolverRuntimeState) bool {
	return stringSlicesEqual(a.ActiveResolvers, b.ActiveResolvers) &&
		stringSlicesEqual(a.StandbyResolvers, b.StandbyResolvers) &&
		stringSlicesEqual(a.ValidResolvers, b.ValidResolvers) &&
		resolverDetailsEqual(a.ResolverDetails, b.ResolverDetails) &&
		a.TotalCount == b.TotalCount &&
		a.ActiveCount == b.ActiveCount &&
		a.StandbyCount == b.StandbyCount &&
		a.ValidCount == b.ValidCount &&
		a.RejectedCount == b.RejectedCount &&
		a.PendingCount == b.PendingCount &&
		a.ActiveComplete == b.ActiveComplete &&
		a.StandbyComplete == b.StandbyComplete &&
		a.ValidComplete == b.ValidComplete
}

func resolverDetailsEqual(a, b []model.ResolverRuntimeDetail) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

func (m *Manager) notifyTargetUnavailable(active *activeProcess) {
	m.markTargetUnavailable(active, true)
}

func (m *Manager) markTargetUnavailable(active *activeProcess, emitError bool) {
	now := time.Now()
	shouldEmit := false
	m.mu.Lock()
	if m.active != active {
		m.mu.Unlock()
		return
	}
	if !active.targetUnavailable {
		active.targetUnavailable = true
		active.targetUnavailableAt = now
	}
	if emitError && !active.targetUnavailableSent {
		active.targetUnavailableSent = true
		shouldEmit = true
	}
	m.mu.Unlock()
	if shouldEmit {
		m.runtimeError(targetServerUnavailableMessage)
	}
}

func (m *Manager) waitForExit(active *activeProcess) {
	err := active.cmd.Wait()
	active.waitErr = err
	close(active.done)
	active.cancel()
	m.mu.Lock()
	if m.active == active {
		m.active = nil
	}
	stopping := active.stopping
	m.mu.Unlock()
	if stopping {
		m.cleanup(active)
		return
	}
	m.stopXray(active)
	m.cleanup(active)
	if err != nil {
		m.runtimeError(fmt.Sprintf("MasterDNS stopped unexpectedly: %v", err))
		m.state(model.RuntimeFailed, "MasterDNS stopped unexpectedly")
		return
	}
	m.state(model.RuntimeDisconnected, "MasterDNS stopped")
}

func (m *Manager) waitForXrayExit(active *activeProcess) {
	err := active.xrayCmd.Wait()
	close(active.xrayDone)
	if active.xrayCancel != nil {
		active.xrayCancel()
	}
	m.mu.Lock()
	activeStillCurrent := m.active == active
	stopping := active.stopping
	if activeStillCurrent && !stopping {
		active.stopping = true
		m.active = nil
	}
	m.mu.Unlock()
	if stopping || !activeStillCurrent {
		return
	}
	m.stopMasterDNS(active)
	m.cleanup(active)
	if err != nil {
		m.runtimeError(fmt.Sprintf("xray stopped unexpectedly: %v", err))
	} else {
		m.runtimeError("xray stopped unexpectedly")
	}
	m.state(model.RuntimeFailed, "xray proxy stopped unexpectedly")
}

func (m *Manager) isActive(active *activeProcess) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active == active && !active.stopping
}

func (m *Manager) cleanup(active *activeProcess) {
	m.stopMTUResolverStateMonitor(active)
	m.stopTrafficMonitor(active)
	m.restoreSystemProxyGuard(active)
	m.restoreTunRouteGuard(active)
	_ = os.Remove(active.configFile)
	if active.resolversOwned {
		_ = os.Remove(active.resolvers)
	}
	_ = os.Remove(active.mtuScanControlFile)
	_ = os.Remove(active.mtuResolverStateFile)
	_ = os.Remove(active.masterPIDFile)
	_ = os.Remove(active.xrayConfigFile)
	_ = os.Remove(active.xrayPIDFile)
	_ = os.Remove(active.systemProxySnapshotFile)
	_ = os.Remove(active.tunRouteSnapshotFile)
}

func (m *Manager) stopMTUResolverStateMonitor(active *activeProcess) {
	active.resolverStateStopOnce.Do(func() {
		if active.resolverStateCancel == nil {
			return
		}
		active.resolverStateCancel()
		if active.resolverStateDone != nil {
			select {
			case <-active.resolverStateDone:
			case <-time.After(m.options.StopTimeout):
			}
		}
		active.resolverStateCancel = nil
		active.resolverStateDone = nil
	})
}

func (m *Manager) stopTrafficMonitor(active *activeProcess) {
	active.trafficStopOnce.Do(func() {
		if active.trafficCancel == nil {
			return
		}
		active.trafficCancel()
		if active.trafficDone != nil {
			select {
			case <-active.trafficDone:
			case <-time.After(m.options.StopTimeout):
			}
		}
		active.trafficCancel = nil
		active.trafficDone = nil
	})
}

func (m *Manager) stopMasterDNS(active *activeProcess) {
	if active.cmd == nil || active.cmd.Process == nil {
		return
	}
	if err := active.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = active.cmd.Process.Kill()
	}
	select {
	case <-active.done:
	case <-time.After(m.options.StopTimeout):
		active.cancel()
		_ = active.cmd.Process.Kill()
		<-active.done
	}
}

func (m *Manager) stopXray(active *activeProcess) {
	if active.xrayCmd == nil || active.xrayCmd.Process == nil || active.xrayDone == nil {
		return
	}
	m.log("Stopping xray gracefully")
	if err := active.xrayCmd.Process.Signal(os.Interrupt); err != nil {
		m.log(fmt.Sprintf("xray graceful stop failed, forcing termination: %v", err))
		_ = active.xrayCmd.Process.Kill()
	}
	select {
	case <-active.xrayDone:
		m.log("xray stopped gracefully")
	case <-time.After(m.options.XrayStopTimeout):
		m.log(fmt.Sprintf("xray did not stop within %s; forcing termination", m.options.XrayStopTimeout))
		if active.xrayCancel != nil {
			active.xrayCancel()
		}
		_ = active.xrayCmd.Process.Kill()
		<-active.xrayDone
	}
}

func (m *Manager) log(line string) {
	if m.callbacks.OnLog == nil {
		return
	}
	if summary, ok := m.reserveLogEvent(time.Now()); summary != "" {
		m.callbacks.OnLog(summary)
		if !ok {
			return
		}
	} else if !ok {
		return
	}
	m.callbacks.OnLog(line)
}

func (m *Manager) debugLogf(enabled bool, format string, args ...any) {
	if !enabled {
		return
	}
	m.log(fmt.Sprintf(format, args...))
}

func (m *Manager) reserveLogEvent(now time.Time) (string, bool) {
	m.logMu.Lock()
	defer m.logMu.Unlock()

	if m.logWindowStart.IsZero() || now.Sub(m.logWindowStart) >= time.Second {
		dropped := m.logDropped
		m.logWindowStart = now
		m.logWindowCount = 0
		m.logDropped = 0
		if dropped > 0 {
			m.logWindowCount++
			return fmt.Sprintf("Runtime log output throttled: dropped %d lines in the last second", dropped), m.logWindowCount < runtimeLogEventsPerSecond
		}
	}

	if m.logWindowCount < runtimeLogEventsPerSecond {
		m.logWindowCount++
		return "", true
	}
	m.logDropped++
	return "", false
}

func masterDNSDebugLogsEnabled(settings model.SettingsProfile) bool {
	return strings.EqualFold(strings.TrimSpace(settings.LogLevel), "DEBUG")
}

func countResolverLines(raw string) int {
	count := 0
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func (m *Manager) state(status, message string) {
	if m.callbacks.OnState != nil {
		m.callbacks.OnState(status, message)
	}
}

func (m *Manager) progress(progress model.ConnectionProgress) {
	if m.callbacks.OnProgress != nil {
		m.callbacks.OnProgress(progress)
	}
}

func (m *Manager) resolverState(state model.ResolverRuntimeState) {
	if m.callbacks.OnResolverState != nil {
		m.callbacks.OnResolverState(state)
	}
}

func (m *Manager) stats(stats model.TrafficStats) {
	if m.callbacks.OnStats != nil {
		m.callbacks.OnStats(stats)
	}
}

func (m *Manager) trafficStatus(message string) {
	if m.callbacks.OnTrafficStatus != nil {
		m.callbacks.OnTrafficStatus(message)
	}
}

func (m *Manager) runtimeError(message string) {
	if m.callbacks.OnError != nil {
		m.callbacks.OnError(message)
	}
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if goruntime.GOOS == "windows" {
		return true
	}
	if info.Mode()&0o111 != 0 {
		return true
	}
	_ = os.Chmod(path, info.Mode()|0o755)
	info, err = os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func findClientBinaryInDir(dir string) (string, bool) {
	if strings.TrimSpace(dir) == "" {
		return "", false
	}
	for _, name := range helperNameCandidates() {
		candidate := filepath.Join(dir, name)
		if isExecutableFile(candidate) {
			return candidate, true
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		lower := strings.ToLower(entry.Name())
		if !strings.Contains(lower, "client") {
			continue
		}
		if !strings.Contains(lower, "masterdns") && !strings.Contains(lower, "masterdnsvpn") {
			continue
		}
		candidate := filepath.Join(dir, entry.Name())
		if isExecutableFile(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func findXrayBinaryInDir(dir string) (string, bool) {
	if strings.TrimSpace(dir) == "" {
		return "", false
	}
	for _, name := range xrayNameCandidates() {
		candidate := filepath.Join(dir, name)
		if isExecutableFile(candidate) {
			return candidate, true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		lower := strings.ToLower(entry.Name())
		if !strings.Contains(lower, "xray") {
			continue
		}
		candidate := filepath.Join(dir, entry.Name())
		if isExecutableFile(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func helperPlatformName() string {
	name := "masterdns-client-" + goruntime.GOOS + "-" + goruntime.GOARCH
	if goruntime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func xrayPlatformName() string {
	name := "xray-" + goruntime.GOOS + "-" + goruntime.GOARCH
	if goruntime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func helperNameCandidates() []string {
	platformName := helperPlatformName()
	exe := ""
	if goruntime.GOOS == "windows" {
		exe = ".exe"
	}
	platformLabel := map[string]string{
		"darwin":  "MacOS",
		"windows": "Windows",
		"linux":   "Linux",
	}[goruntime.GOOS]
	if platformLabel == "" {
		platformLabel = goruntime.GOOS
	}
	archLabel := strings.ToUpper(goruntime.GOARCH)
	if goruntime.GOARCH == "amd64" {
		archLabel = "AMD64"
	}
	return []string{
		platformName,
		"masterdns-client" + exe,
		"masterdns_client" + exe,
		"masterdnsvpn-client" + exe,
		"masterdnsvpn_client" + exe,
		"MasterDnsVPN_Client" + exe,
		"MasterDnsVPN_Client_" + platformLabel + "_" + archLabel + exe,
	}
}

func xrayNameCandidates() []string {
	platformName := xrayPlatformName()
	exe := ""
	if goruntime.GOOS == "windows" {
		exe = ".exe"
	}
	return []string{
		platformName,
		"xray" + exe,
	}
}

func appendUnique(values []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func candidateBases() []string {
	var bases []string
	if cwd, err := os.Getwd(); err == nil {
		bases = appendBaseCandidates(bases, cwd)
		if filepath.Base(cwd) != "desktop" {
			bases = appendBaseCandidates(bases, filepath.Join(cwd, "desktop"))
		}
		bases = appendBaseCandidates(bases, filepath.Dir(cwd), filepath.Join(filepath.Dir(cwd), "desktop"))
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		bases = appendBaseCandidates(
			bases,
			exeDir,
			filepath.Join(exeDir, ".."),
			filepath.Join(exeDir, "..", "Resources"),
			filepath.Join(exeDir, "..", "..", "Resources"),
			filepath.Join(exeDir, "..", "..", ".."),
		)
	}
	if runtimeDir := strings.TrimSpace(os.Getenv("WHITEDNS_RUNTIME_DIR")); runtimeDir != "" {
		bases = appendBaseCandidates(bases, filepath.Dir(runtimeDir))
	}
	return bases
}

func appendBaseCandidates(values []string, candidates ...string) []string {
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if candidate == "." || candidate == string(filepath.Separator) {
			continue
		}
		values = appendUnique(values, candidate)
	}
	return values
}

func writePIDFile(path string, pid int) error {
	if strings.TrimSpace(path) == "" || pid <= 0 {
		return nil
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0o600)
}

func cleanupStaleLaunchFiles(runtimeDir string, stopTimeout time.Duration, log func(string), platform string, runner SystemProxyCommandRunner) error {
	if stopTimeout <= 0 {
		stopTimeout = 10 * time.Second
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".wd-") || !strings.HasSuffix(entry.Name(), ".pid") {
			continue
		}
		stopStaleProcessFromPIDFile(filepath.Join(runtimeDir, entry.Name()), stopTimeout, log)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".wd-") || !strings.HasSuffix(entry.Name(), ".system-proxy.json") {
			continue
		}
		path := filepath.Join(runtimeDir, entry.Name())
		restoreCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := restoreSystemProxySnapshotFile(restoreCtx, path, platform, runner)
		cancel()
		if err != nil {
			logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup warning: failed to restore stale system proxy snapshot %s: %v", path, err))
		} else {
			logRuntimeCleanup(log, "Runtime cleanup restored stale system proxy settings")
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".wd-") || !strings.HasSuffix(entry.Name(), ".tun-routes.json") {
			continue
		}
		path := filepath.Join(runtimeDir, entry.Name())
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := restoreTunRouteSnapshotFile(restoreCtx, path, platform, runner)
		cancel()
		if err != nil {
			logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup warning: failed to restore stale TUN routes %s: %v", path, err))
		} else {
			logRuntimeCleanup(log, "Runtime cleanup restored stale TUN routes")
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".wd-") {
			continue
		}
		if !isLaunchFile(entry.Name()) {
			continue
		}
		_ = os.Remove(filepath.Join(runtimeDir, entry.Name()))
	}
	return nil
}

func isLaunchFile(name string) bool {
	switch {
	case strings.HasSuffix(name, ".toml"):
		return true
	case strings.HasSuffix(name, ".resolvers"):
		return true
	case strings.HasSuffix(name, ".mtu-scan-control"):
		return true
	case strings.HasSuffix(name, ".mtu-resolvers.log"):
		return true
	case strings.HasSuffix(name, ".xray.json"):
		return true
	case strings.HasSuffix(name, ".sing-box.json"):
		return true
	case strings.HasSuffix(name, ".system-proxy.json"):
		return true
	case strings.HasSuffix(name, ".tun-routes.json"):
		return true
	case strings.HasSuffix(name, ".pid"):
		return true
	default:
		return false
	}
}

func stopStaleProcessFromPIDFile(path string, stopTimeout time.Duration, log func(string)) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return
	}
	pidText := strings.TrimSpace(fields[0])
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if err := proc.Signal(os.Interrupt); err != nil {
		logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup warning: stale process %d did not accept graceful stop: %v", pid, err))
		_ = proc.Kill()
		return
	}
	deadline := time.Now().Add(stopTimeout)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup stopped stale process %d gracefully", pid))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup warning: stale process %d did not stop within %s; forcing termination", pid, stopTimeout))
	_ = proc.Kill()
}

func logRuntimeCleanup(log func(string), line string) {
	if log != nil {
		log(line)
	}
}

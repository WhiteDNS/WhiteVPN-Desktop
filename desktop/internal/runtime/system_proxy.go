package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"
)

type SystemProxyCommandRunner func(ctx context.Context, name string, args ...string) (string, error)

type systemProxyGuard interface {
	Apply(context.Context) error
	Verify(context.Context) error
	Restore(context.Context) error
	Snapshot() systemProxySnapshot
}

type systemProxySnapshot struct {
	Platform string            `json:"platform"`
	Backend  string            `json:"backend"`
	Version  string            `json:"version,omitempty"`
	Values   map[string]string `json:"values"`
}

type linuxSystemProxyGuard struct {
	runner       SystemProxyCommandRunner
	expectedHost string
	expectedPort int
	protocol     string
	snapshot     systemProxySnapshot
}

type macOSSystemProxyGuard struct {
	runner       SystemProxyCommandRunner
	expectedHost string
	expectedPort int
	protocol     string
	services     []string
	snapshot     systemProxySnapshot
}

type windowsSystemProxyGuard struct {
	runner       SystemProxyCommandRunner
	expectedHost string
	expectedPort int
	protocol     string
	snapshot     systemProxySnapshot
}

var gnomeSystemProxyKeys = []string{
	"org.gnome.system.proxy|mode",
	"org.gnome.system.proxy|ignore-hosts",
	"org.gnome.system.proxy.http|enabled",
	"org.gnome.system.proxy.http|host",
	"org.gnome.system.proxy.http|port",
	"org.gnome.system.proxy.http|use-authentication",
	"org.gnome.system.proxy.http|authentication-user",
	"org.gnome.system.proxy.http|authentication-password",
	"org.gnome.system.proxy.https|host",
	"org.gnome.system.proxy.https|port",
	"org.gnome.system.proxy.socks|host",
	"org.gnome.system.proxy.socks|port",
}

var kdeSystemProxyKeys = []string{
	"ProxyType",
	"httpProxy",
	"httpsProxy",
	"socksProxy",
	"ftpProxy",
	"NoProxyFor",
	"Proxy Config Script",
}

func (m *Manager) prepareSystemProxyGuard(ctx context.Context, enabled bool, proxyProtocol string, listenIP string, listenPort int) (systemProxyGuard, error) {
	if !enabled {
		return nil, nil
	}
	platform := m.options.SystemProxyPlatform
	if strings.TrimSpace(platform) == "" {
		platform = goruntime.GOOS
	}
	var guard systemProxyGuard
	var err error
	switch platform {
	case "linux":
		guard, err = newLinuxSystemProxyGuardWithProtocol(ctx, m.options.SystemProxyRunner, listenIP, listenPort, proxyProtocol)
		if err != nil {
			return nil, fmt.Errorf("Linux system proxy is enabled, but this desktop environment is unsupported or required tools are missing. Install gsettings for GNOME or kreadconfig/kwriteconfig for KDE, or disable system proxy: %w", err)
		}
	case "darwin":
		guard, err = newMacOSSystemProxyGuard(ctx, m.options.SystemProxyRunner, listenIP, listenPort, proxyProtocol)
		if err != nil {
			return nil, fmt.Errorf("macOS system proxy is enabled, but networksetup could not be used: %w", err)
		}
	case "windows":
		guard, err = newWindowsSystemProxyGuard(ctx, m.options.SystemProxyRunner, listenIP, listenPort, proxyProtocol)
		if err != nil {
			return nil, fmt.Errorf("Windows system proxy is enabled, but the proxy registry settings could not be updated: %w", err)
		}
	default:
		return nil, nil
	}
	if err := guard.Apply(ctx); err != nil {
		restoreSystemProxyGuardWithLog(guard, m.log)
		return nil, err
	}
	return guard, nil
}

func (m *Manager) waitForSystemProxy(ctx context.Context, active *activeProcess, _ string, _ int) error {
	if active == nil || active.systemProxyGuard == nil {
		return nil
	}
	verifyCtx, cancel := context.WithTimeout(ctx, m.options.SystemProxyVerifyTimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := active.systemProxyGuard.Verify(verifyCtx); err == nil {
			m.log("System proxy applied")
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-verifyCtx.Done():
			if lastErr != nil {
				return fmt.Errorf("system proxy did not apply: %w", lastErr)
			}
			return fmt.Errorf("system proxy did not apply: %w", verifyCtx.Err())
		case <-ticker.C:
		}
	}
}

func (m *Manager) restoreSystemProxyGuard(active *activeProcess) {
	if active == nil {
		return
	}
	active.systemProxyRestoreOnce.Do(func() {
		restoreSystemProxyGuardWithLog(active.systemProxyGuard, m.log)
	})
}

func restoreSystemProxyGuardWithLog(guard systemProxyGuard, log func(string)) {
	if guard == nil {
		return
	}
	restoreCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := guard.Restore(restoreCtx); err != nil {
		logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup warning: failed to restore system proxy settings: %v", err))
		return
	}
	logRuntimeCleanup(log, "System proxy settings restored")
}

func writeSystemProxySnapshotFile(path string, guard systemProxyGuard) error {
	if guard == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := json.MarshalIndent(guard.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func restoreSystemProxySnapshotFile(ctx context.Context, path string, platform string, runner SystemProxyCommandRunner) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snapshot systemProxySnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Platform == "" {
		snapshot.Platform = firstNonEmptyString(platform, goruntime.GOOS)
	}
	switch snapshot.Platform {
	case "linux":
		return restoreLinuxSystemProxySnapshot(ctx, snapshot, defaultSystemProxyRunner(runner))
	case "darwin":
		return restoreMacOSSystemProxySnapshot(ctx, snapshot, defaultSystemProxyRunner(runner))
	case "windows":
		return restoreWindowsSystemProxySnapshot(ctx, snapshot, defaultSystemProxyRunner(runner))
	default:
		return nil
	}
}

func newLinuxSystemProxyGuard(ctx context.Context, runner SystemProxyCommandRunner, listenIP string, listenPort int) (systemProxyGuard, error) {
	return newLinuxSystemProxyGuardWithProtocol(ctx, runner, listenIP, listenPort, "socks")
}

func newLinuxSystemProxyGuardWithProtocol(ctx context.Context, runner SystemProxyCommandRunner, listenIP string, listenPort int, protocol string) (systemProxyGuard, error) {
	runner = defaultSystemProxyRunner(runner)
	expectedHost := normalizeSystemProxyHost(listenIP)
	desktop := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP") + " " + os.Getenv("DESKTOP_SESSION"))
	if strings.Contains(desktop, "kde") {
		if guard, err := newKDESystemProxyGuard(ctx, runner, expectedHost, listenPort, protocol); err == nil {
			return guard, nil
		}
		return newGNOMESystemProxyGuard(ctx, runner, expectedHost, listenPort, protocol)
	}
	if guard, err := newGNOMESystemProxyGuard(ctx, runner, expectedHost, listenPort, protocol); err == nil {
		return guard, nil
	}
	return newKDESystemProxyGuard(ctx, runner, expectedHost, listenPort, protocol)
}

func newGNOMESystemProxyGuard(ctx context.Context, runner SystemProxyCommandRunner, expectedHost string, expectedPort int, protocol string) (systemProxyGuard, error) {
	if _, err := runner(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode"); err != nil {
		return nil, err
	}
	values := make(map[string]string, len(gnomeSystemProxyKeys))
	for _, key := range gnomeSystemProxyKeys {
		schema, name, _ := strings.Cut(key, "|")
		output, err := runner(ctx, "gsettings", "get", schema, name)
		if err != nil {
			return nil, err
		}
		values[key] = strings.TrimSpace(output)
	}
	return &linuxSystemProxyGuard{
		runner:       runner,
		expectedHost: expectedHost,
		expectedPort: expectedPort,
		protocol:     normalizeSystemProxyProtocol(protocol),
		snapshot: systemProxySnapshot{
			Platform: "linux",
			Backend:  "gnome",
			Values:   values,
		},
	}, nil
}

func newKDESystemProxyGuard(ctx context.Context, runner SystemProxyCommandRunner, expectedHost string, expectedPort int, protocol string) (systemProxyGuard, error) {
	var lastErr error
	for _, version := range []string{"6", "5"} {
		readCommand := "kreadconfig" + version
		if _, err := runner(ctx, readCommand, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType"); err != nil {
			lastErr = err
			continue
		}
		values := make(map[string]string, len(kdeSystemProxyKeys))
		for _, key := range kdeSystemProxyKeys {
			output, err := runner(ctx, readCommand, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key)
			if err != nil {
				return nil, err
			}
			values[key] = strings.TrimSpace(output)
		}
		return &linuxSystemProxyGuard{
			runner:       runner,
			expectedHost: expectedHost,
			expectedPort: expectedPort,
			protocol:     normalizeSystemProxyProtocol(protocol),
			snapshot: systemProxySnapshot{
				Platform: "linux",
				Backend:  "kde",
				Version:  version,
				Values:   values,
			},
		}, nil
	}
	return nil, lastErr
}

func (g *linuxSystemProxyGuard) Apply(ctx context.Context) error {
	switch g.snapshot.Backend {
	case "gnome":
		return g.applyGNOME(ctx)
	case "kde":
		return g.applyKDE(ctx)
	default:
		return fmt.Errorf("unsupported Linux proxy backend %q", g.snapshot.Backend)
	}
}

func (g *linuxSystemProxyGuard) Verify(ctx context.Context) error {
	switch g.snapshot.Backend {
	case "gnome":
		return g.verifyGNOME(ctx)
	case "kde":
		return g.verifyKDE(ctx)
	default:
		return fmt.Errorf("unsupported Linux proxy backend %q", g.snapshot.Backend)
	}
}

func (g *linuxSystemProxyGuard) Restore(ctx context.Context) error {
	return restoreLinuxSystemProxySnapshot(ctx, g.snapshot, g.runner)
}

func (g *linuxSystemProxyGuard) Snapshot() systemProxySnapshot {
	return g.snapshot
}

func (g *linuxSystemProxyGuard) applyGNOME(ctx context.Context) error {
	host := strconv.Quote(g.expectedHost)
	port := strconv.Itoa(g.expectedPort)
	commands := [][]string{
		{"set", "org.gnome.system.proxy.http", "enabled", "true"},
		{"set", "org.gnome.system.proxy.http", "host", host},
		{"set", "org.gnome.system.proxy.http", "port", port},
		{"set", "org.gnome.system.proxy.http", "use-authentication", "false"},
		{"set", "org.gnome.system.proxy.https", "host", host},
		{"set", "org.gnome.system.proxy.https", "port", port},
	}
	if g.protocol != "http" {
		commands = append(commands,
			[]string{"set", "org.gnome.system.proxy.socks", "host", host},
			[]string{"set", "org.gnome.system.proxy.socks", "port", port},
		)
	}
	commands = append(commands, []string{"set", "org.gnome.system.proxy", "mode", strconv.Quote("manual")})
	for _, args := range commands {
		if _, err := g.runner(ctx, "gsettings", args...); err != nil {
			return err
		}
	}
	return nil
}

func (g *linuxSystemProxyGuard) applyKDE(ctx context.Context) error {
	writeCommand := "kwriteconfig" + firstNonEmptyString(g.snapshot.Version, "6")
	httpProxy := "http://" + net.JoinHostPort(g.expectedHost, strconv.Itoa(g.expectedPort))
	commands := [][]string{
		{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"},
		{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", httpProxy},
		{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", httpProxy},
	}
	if g.protocol != "http" {
		commands = append(commands, []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "socks://" + net.JoinHostPort(g.expectedHost, strconv.Itoa(g.expectedPort))})
	}
	for _, args := range commands {
		if _, err := g.runner(ctx, writeCommand, args...); err != nil {
			return err
		}
	}
	return nil
}

func (g *linuxSystemProxyGuard) verifyGNOME(ctx context.Context) error {
	mode, err := g.runner(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode")
	if err != nil {
		return err
	}
	if !strings.EqualFold(unquoteSystemProxyValue(mode), "manual") {
		return fmt.Errorf("GNOME proxy mode is %s, expected manual", strings.TrimSpace(mode))
	}
	checks := []struct {
		schema string
	}{
		{schema: "org.gnome.system.proxy.http"},
		{schema: "org.gnome.system.proxy.https"},
		{schema: "org.gnome.system.proxy.socks"},
	}
	for _, check := range checks {
		host, hostErr := g.runner(ctx, "gsettings", "get", check.schema, "host")
		port, portErr := g.runner(ctx, "gsettings", "get", check.schema, "port")
		if hostErr == nil && portErr == nil && systemProxyEndpointMatches(host, port, g.expectedHost, g.expectedPort) {
			return nil
		}
	}
	return fmt.Errorf("GNOME proxy is not pointing at %s:%d", g.expectedHost, g.expectedPort)
}

func (g *linuxSystemProxyGuard) verifyKDE(ctx context.Context) error {
	readCommand := "kreadconfig" + firstNonEmptyString(g.snapshot.Version, "6")
	proxyType, err := g.runner(ctx, readCommand, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType")
	if err != nil {
		return err
	}
	if strings.TrimSpace(proxyType) != "1" {
		return fmt.Errorf("KDE proxy type is %s, expected 1", strings.TrimSpace(proxyType))
	}
	for _, key := range []string{"httpProxy", "httpsProxy", "socksProxy"} {
		value, err := g.runner(ctx, readCommand, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key)
		if err == nil && kdeProxyValueMatches(value, g.expectedHost, g.expectedPort) {
			return nil
		}
	}
	return fmt.Errorf("KDE proxy is not pointing at %s:%d", g.expectedHost, g.expectedPort)
}

func restoreLinuxSystemProxySnapshot(ctx context.Context, snapshot systemProxySnapshot, runner SystemProxyCommandRunner) error {
	runner = defaultSystemProxyRunner(runner)
	switch snapshot.Backend {
	case "gnome":
		for _, key := range gnomeSystemProxyKeys {
			if key == "org.gnome.system.proxy|mode" {
				continue
			}
			value, ok := snapshot.Values[key]
			if !ok {
				continue
			}
			schema, name, _ := strings.Cut(key, "|")
			if _, err := runner(ctx, "gsettings", "set", schema, name, value); err != nil {
				return err
			}
		}
		if value, ok := snapshot.Values["org.gnome.system.proxy|mode"]; ok {
			if _, err := runner(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", value); err != nil {
				return err
			}
		}
		return nil
	case "kde":
		writeCommand := "kwriteconfig" + firstNonEmptyString(snapshot.Version, "6")
		for _, key := range kdeSystemProxyKeys {
			value, ok := snapshot.Values[key]
			if !ok {
				continue
			}
			if _, err := runner(ctx, writeCommand, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, value); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported Linux proxy backend %q", snapshot.Backend)
	}
}

func newMacOSSystemProxyGuard(ctx context.Context, runner SystemProxyCommandRunner, listenIP string, listenPort int, protocol string) (systemProxyGuard, error) {
	runner = defaultSystemProxyRunner(runner)
	servicesRaw, err := runner(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	services := parseMacOSNetworkServices(servicesRaw)
	if len(services) == 0 {
		return nil, fmt.Errorf("no macOS network services found")
	}
	values := map[string]string{}
	for _, service := range services {
		for key, args := range map[string][]string{
			"web":    {"-getwebproxy", service},
			"secure": {"-getsecurewebproxy", service},
			"socks":  {"-getsocksfirewallproxy", service},
		} {
			output, _ := runner(ctx, "networksetup", args...)
			values[service+"|"+key] = output
		}
	}
	return &macOSSystemProxyGuard{
		runner:       runner,
		expectedHost: normalizeSystemProxyHost(listenIP),
		expectedPort: listenPort,
		protocol:     normalizeSystemProxyProtocol(protocol),
		services:     services,
		snapshot: systemProxySnapshot{
			Platform: "darwin",
			Backend:  "networksetup",
			Values:   values,
		},
	}, nil
}

func (g *macOSSystemProxyGuard) Apply(ctx context.Context) error {
	port := strconv.Itoa(g.expectedPort)
	for _, service := range g.services {
		commands := [][]string{
			{"-setwebproxy", service, g.expectedHost, port},
			{"-setwebproxystate", service, "on"},
			{"-setsecurewebproxy", service, g.expectedHost, port},
			{"-setsecurewebproxystate", service, "on"},
		}
		if g.protocol != "http" {
			commands = append(commands,
				[]string{"-setsocksfirewallproxy", service, g.expectedHost, port},
				[]string{"-setsocksfirewallproxystate", service, "on"},
			)
		}
		for _, args := range commands {
			if _, err := g.runner(ctx, "networksetup", args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *macOSSystemProxyGuard) Verify(ctx context.Context) error {
	for _, service := range g.services {
		for _, args := range [][]string{{"-getwebproxy", service}, {"-getsecurewebproxy", service}, {"-getsocksfirewallproxy", service}} {
			output, err := g.runner(ctx, "networksetup", args...)
			if err == nil && macOSProxyOutputMatches(output, g.expectedHost, g.expectedPort) {
				return nil
			}
		}
	}
	return fmt.Errorf("macOS proxy is not pointing at %s:%d", g.expectedHost, g.expectedPort)
}

func (g *macOSSystemProxyGuard) Restore(ctx context.Context) error {
	return restoreMacOSSystemProxySnapshot(ctx, g.snapshot, g.runner)
}

func (g *macOSSystemProxyGuard) Snapshot() systemProxySnapshot {
	return g.snapshot
}

func restoreMacOSSystemProxySnapshot(ctx context.Context, snapshot systemProxySnapshot, runner SystemProxyCommandRunner) error {
	runner = defaultSystemProxyRunner(runner)
	for key, output := range snapshot.Values {
		service, proxyType, ok := strings.Cut(key, "|")
		if !ok {
			continue
		}
		setCommand, stateCommand := macOSProxySetCommands(proxyType)
		if setCommand == "" {
			continue
		}
		enabled, host, port := parseMacOSProxyOutput(output)
		if enabled && host != "" && port > 0 {
			if _, err := runner(ctx, "networksetup", setCommand, service, host, strconv.Itoa(port)); err != nil {
				return err
			}
			if _, err := runner(ctx, "networksetup", stateCommand, service, "on"); err != nil {
				return err
			}
		} else if _, err := runner(ctx, "networksetup", stateCommand, service, "off"); err != nil {
			return err
		}
	}
	return nil
}

func newWindowsSystemProxyGuard(ctx context.Context, runner SystemProxyCommandRunner, listenIP string, listenPort int, protocol string) (systemProxyGuard, error) {
	runner = defaultSystemProxyRunner(runner)
	values := map[string]string{}
	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride"} {
		output, _ := runner(ctx, "reg", "query", windowsInternetSettingsKey, "/v", name)
		values[name] = output
	}
	return &windowsSystemProxyGuard{
		runner:       runner,
		expectedHost: normalizeSystemProxyHost(listenIP),
		expectedPort: listenPort,
		protocol:     normalizeSystemProxyProtocol(protocol),
		snapshot: systemProxySnapshot{
			Platform: "windows",
			Backend:  "registry",
			Values:   values,
		},
	}, nil
}

const windowsInternetSettingsKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func (g *windowsSystemProxyGuard) Apply(ctx context.Context) error {
	server := windowsProxyServerValue(g.expectedHost, g.expectedPort, g.protocol)
	if _, err := g.runner(ctx, "reg", "add", windowsInternetSettingsKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"); err != nil {
		return err
	}
	if _, err := g.runner(ctx, "reg", "add", windowsInternetSettingsKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", server, "/f"); err != nil {
		return err
	}
	return nil
}

func (g *windowsSystemProxyGuard) Verify(ctx context.Context) error {
	enable, err := g.runner(ctx, "reg", "query", windowsInternetSettingsKey, "/v", "ProxyEnable")
	if err != nil {
		return err
	}
	server, err := g.runner(ctx, "reg", "query", windowsInternetSettingsKey, "/v", "ProxyServer")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(enable), "0x1") {
		return fmt.Errorf("Windows proxy is disabled")
	}
	if !strings.Contains(server, net.JoinHostPort(g.expectedHost, strconv.Itoa(g.expectedPort))) {
		return fmt.Errorf("Windows proxy is not pointing at %s:%d", g.expectedHost, g.expectedPort)
	}
	return nil
}

func (g *windowsSystemProxyGuard) Restore(ctx context.Context) error {
	return restoreWindowsSystemProxySnapshot(ctx, g.snapshot, g.runner)
}

func (g *windowsSystemProxyGuard) Snapshot() systemProxySnapshot {
	return g.snapshot
}

func restoreWindowsSystemProxySnapshot(ctx context.Context, snapshot systemProxySnapshot, runner SystemProxyCommandRunner) error {
	runner = defaultSystemProxyRunner(runner)
	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride"} {
		value, valueType, ok := parseWindowsRegValue(snapshot.Values[name], name)
		if !ok {
			_, _ = runner(ctx, "reg", "delete", windowsInternetSettingsKey, "/v", name, "/f")
			continue
		}
		if _, err := runner(ctx, "reg", "add", windowsInternetSettingsKey, "/v", name, "/t", valueType, "/d", value, "/f"); err != nil {
			return err
		}
	}
	return nil
}

func defaultSystemProxyRunner(runner SystemProxyCommandRunner) SystemProxyCommandRunner {
	if runner != nil {
		return runner
	}
	return runSystemProxyCommand
}

func runSystemProxyCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsoleWindow(cmd)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func normalizeSystemProxyHost(host string) string {
	host = strings.TrimSpace(host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::", "::1", "localhost":
		return "127.0.0.1"
	default:
		return host
	}
}

func systemProxyEndpointMatches(hostValue string, portValue string, expectedHost string, expectedPort int) bool {
	host := normalizeSystemProxyHost(unquoteSystemProxyValue(hostValue))
	port, err := strconv.Atoi(strings.TrimSpace(portValue))
	return err == nil && host == normalizeSystemProxyHost(expectedHost) && port == expectedPort
}

func kdeProxyValueMatches(value string, expectedHost string, expectedPort int) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		return normalizeSystemProxyHost(parsedHost) == normalizeSystemProxyHost(expectedHost) && parsedPort == strconv.Itoa(expectedPort)
	}
	expectedPortText := strconv.Itoa(expectedPort)
	return strings.Contains(value, normalizeSystemProxyHost(expectedHost)) && strings.Contains(value, expectedPortText)
}

func unquoteSystemProxyValue(value string) string {
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return strings.Trim(value, "'\"")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func normalizeSystemProxyProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http", "mixed":
		return "http"
	default:
		return "socks"
	}
}

func parseMacOSNetworkServices(raw string) []string {
	var services []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "denotes that a network service is disabled") {
			continue
		}
		services = append(services, line)
	}
	return services
}

func macOSProxyOutputMatches(output string, expectedHost string, expectedPort int) bool {
	enabled, host, port := parseMacOSProxyOutput(output)
	return enabled && normalizeSystemProxyHost(host) == normalizeSystemProxyHost(expectedHost) && port == expectedPort
}

func parseMacOSProxyOutput(output string) (bool, string, int) {
	var enabled bool
	var host string
	var port int
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "enabled":
			enabled = strings.EqualFold(value, "yes")
		case "server":
			host = value
		case "port":
			port, _ = strconv.Atoi(value)
		}
	}
	return enabled, host, port
}

func macOSProxySetCommands(proxyType string) (string, string) {
	switch proxyType {
	case "web":
		return "-setwebproxy", "-setwebproxystate"
	case "secure":
		return "-setsecurewebproxy", "-setsecurewebproxystate"
	case "socks":
		return "-setsocksfirewallproxy", "-setsocksfirewallproxystate"
	default:
		return "", ""
	}
}

func windowsProxyServerValue(host string, port int, protocol string) string {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	parts := []string{"http=" + address, "https=" + address}
	if protocol != "http" {
		parts = append(parts, "socks="+address)
	}
	return strings.Join(parts, ";")
}

func parseWindowsRegValue(output string, name string) (string, string, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || !strings.EqualFold(fields[0], name) {
			continue
		}
		valueType := fields[1]
		value := strings.Join(fields[2:], " ")
		if strings.EqualFold(valueType, "REG_DWORD") {
			if strings.HasPrefix(strings.ToLower(value), "0x") {
				parsed, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(value), "0x"), 16, 64)
				if err == nil {
					value = strconv.FormatInt(parsed, 10)
				}
			}
		}
		return value, valueType, true
	}
	return "", "", false
}

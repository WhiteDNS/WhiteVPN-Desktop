package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"
)

type tunRouteGuard interface {
	Apply(context.Context) error
	Restore(context.Context) error
	Snapshot() tunRouteSnapshot
}

type tunRouteSnapshot struct {
	Platform      string            `json:"platform"`
	InterfaceName string            `json:"interfaceName"`
	DeleteRoutes  []tunRouteCommand `json:"deleteRoutes"`
}

type tunRouteCommand struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

type xrayTunRouteGuard struct {
	platform      string
	runner        SystemProxyCommandRunner
	interfaceName string
	ipv6          bool
	serverIPs     []net.IP
	gateway4      string
	dev4          string
	gateway6      string
	dev6          string
	deleteRoutes  []tunRouteCommand
	applied       bool
	restoreForced bool
}

func (m *Manager) prepareTunRouteGuard(ctx context.Context, cfg XrayLaunchConfig, xrayBinaryPath string) (tunRouteGuard, error) {
	if !cfg.TunEnabled {
		return nil, nil
	}
	platform := firstNonEmptyString(m.options.SystemProxyPlatform, goruntime.GOOS)
	interfaceName := strings.TrimSpace(cfg.TunInterfaceName)
	if interfaceName == "" {
		interfaceName = defaultTunInterfaceName(platform)
	}
	runner := defaultSystemProxyRunner(m.options.SystemProxyRunner)
	if platform == "windows" {
		if err := ensureWintunDLL(xrayBinaryPath, m.xraySearchDirs()); err != nil {
			return nil, err
		}
	}
	serverIPs, err := resolveTunServerIPs(ctx, cfg.TunServerHost, cfg.TunIPv6)
	if err != nil {
		return nil, err
	}
	guard := &xrayTunRouteGuard{
		platform:      platform,
		runner:        runner,
		interfaceName: interfaceName,
		ipv6:          cfg.TunIPv6,
		serverIPs:     serverIPs,
	}
	if err := guard.preflight(ctx); err != nil {
		return nil, err
	}
	guard.deleteRoutes = guard.plannedDeleteRoutes()
	return guard, nil
}

func (m *Manager) applyTunRouteGuard(ctx context.Context, active *activeProcess) error {
	if active == nil || active.tunRouteGuard == nil {
		return nil
	}
	applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := active.tunRouteGuard.Apply(applyCtx); err != nil {
		return fmt.Errorf("failed to apply V2Ray TUN routes: %w", err)
	}
	m.log("V2Ray TUN routes applied")
	return nil
}

func (m *Manager) restoreTunRouteGuard(active *activeProcess) {
	if active == nil {
		return
	}
	active.tunRouteRestoreOnce.Do(func() {
		restoreTunRouteGuardWithLog(active.tunRouteGuard, m.log)
	})
}

func restoreTunRouteGuardWithLog(guard tunRouteGuard, log func(string)) {
	if guard == nil {
		return
	}
	restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := guard.Restore(restoreCtx); err != nil {
		logRuntimeCleanup(log, fmt.Sprintf("Runtime cleanup warning: failed to restore TUN routes: %v", err))
		return
	}
	logRuntimeCleanup(log, "V2Ray TUN routes restored")
}

func writeTunRouteSnapshotFile(path string, guard tunRouteGuard) error {
	if guard == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := json.MarshalIndent(guard.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func restoreTunRouteSnapshotFile(ctx context.Context, path string, platform string, runner SystemProxyCommandRunner) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snapshot tunRouteSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Platform == "" {
		snapshot.Platform = firstNonEmptyString(platform, goruntime.GOOS)
	}
	guard := &xrayTunRouteGuard{
		platform:      snapshot.Platform,
		runner:        defaultSystemProxyRunner(runner),
		interfaceName: snapshot.InterfaceName,
		deleteRoutes:  snapshot.DeleteRoutes,
		restoreForced: true,
	}
	return guard.Restore(ctx)
}

func (g *xrayTunRouteGuard) Snapshot() tunRouteSnapshot {
	return tunRouteSnapshot{
		Platform:      g.platform,
		InterfaceName: g.interfaceName,
		DeleteRoutes:  append([]tunRouteCommand(nil), g.deleteRoutes...),
	}
}

func (g *xrayTunRouteGuard) Apply(ctx context.Context) error {
	if err := g.waitForInterface(ctx); err != nil {
		return err
	}
	commands, err := g.plannedAddRoutes(ctx)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := g.runRouteMutation(ctx, command); err != nil {
			_ = g.Restore(context.Background())
			return err
		}
		g.applied = true
	}
	return nil
}

func (g *xrayTunRouteGuard) Restore(ctx context.Context) error {
	if !g.applied && !g.restoreForced {
		return nil
	}
	var firstErr error
	for idx := len(g.deleteRoutes) - 1; idx >= 0; idx-- {
		if err := g.runRouteMutation(ctx, g.deleteRoutes[idx]); err != nil && !benignRouteDeleteError(err) && firstErr == nil {
			firstErr = err
		}
	}
	g.applied = false
	return firstErr
}

func (g *xrayTunRouteGuard) preflight(ctx context.Context) error {
	switch g.platform {
	case "windows":
		gateway, err := windowsDefaultGateway(ctx, g.runner, "IPv4")
		if err != nil {
			return fmt.Errorf("Windows TUN route preflight failed: %w", err)
		}
		g.gateway4 = gateway
		if g.ipv6 {
			g.gateway6, _ = windowsDefaultGateway(ctx, g.runner, "IPv6")
		}
	case "darwin":
		output, err := g.runner(ctx, "route", "-n", "get", "default")
		if err != nil {
			return fmt.Errorf("macOS TUN route preflight failed: %w", err)
		}
		g.gateway4, g.dev4 = parseDarwinDefaultRoute(output)
		if g.gateway4 == "" && g.dev4 == "" {
			return errors.New("macOS TUN route preflight failed: default IPv4 gateway not found")
		}
		if g.ipv6 {
			if output, err := g.runner(ctx, "route", "-n", "get", "-inet6", "default"); err == nil {
				g.gateway6, g.dev6 = parseDarwinDefaultRoute(output)
			}
		}
	case "linux":
		output, err := g.runner(ctx, "ip", "route", "show", "default")
		if err != nil {
			return fmt.Errorf("Linux TUN route preflight failed: %w", err)
		}
		g.gateway4, g.dev4 = parseLinuxDefaultRoute(output)
		if g.gateway4 == "" && g.dev4 == "" {
			return errors.New("Linux TUN route preflight failed: default IPv4 route not found")
		}
		if g.ipv6 {
			if output, err := g.runner(ctx, "ip", "-6", "route", "show", "default"); err == nil {
				g.gateway6, g.dev6 = parseLinuxDefaultRoute(output)
			}
		}
	default:
		return fmt.Errorf("TUN route management is unsupported on %s", g.platform)
	}
	return nil
}

func (g *xrayTunRouteGuard) plannedAddRoutes(ctx context.Context) ([]tunRouteCommand, error) {
	switch g.platform {
	case "windows":
		index, err := g.windowsInterfaceIndex(ctx)
		if err != nil {
			return nil, err
		}
		return g.windowsAddRoutes(index), nil
	case "darwin":
		return g.darwinAddRoutes(), nil
	case "linux":
		return g.linuxAddRoutes(), nil
	default:
		return nil, fmt.Errorf("TUN route management is unsupported on %s", g.platform)
	}
}

func (g *xrayTunRouteGuard) plannedDeleteRoutes() []tunRouteCommand {
	switch g.platform {
	case "windows":
		return g.windowsDeleteRoutes()
	case "darwin":
		return g.darwinDeleteRoutes()
	case "linux":
		return g.linuxDeleteRoutes()
	default:
		return nil
	}
}

func (g *xrayTunRouteGuard) windowsAddRoutes(interfaceIndex string) []tunRouteCommand {
	commands := make([]tunRouteCommand, 0, len(g.serverIPs)+4)
	for _, ip := range g.serverIPs {
		if ip.To4() != nil {
			commands = append(commands, tunRouteCommand{"route", []string{"add", ip.String(), "mask", "255.255.255.255", g.gateway4, "metric", "1"}})
		} else if g.ipv6 && g.gateway6 != "" {
			commands = append(commands, tunRouteCommand{"netsh", []string{"interface", "ipv6", "add", "route", ip.String() + "/128", g.interfaceName, g.gateway6, "publish=no"}})
		}
	}
	commands = append(commands,
		tunRouteCommand{"route", []string{"add", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", interfaceIndex, "metric", "1"}},
		tunRouteCommand{"route", []string{"add", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", interfaceIndex, "metric", "1"}},
	)
	if g.ipv6 {
		commands = append(commands,
			tunRouteCommand{"netsh", []string{"interface", "ipv6", "add", "route", "::/1", g.interfaceName, "::", "publish=no"}},
			tunRouteCommand{"netsh", []string{"interface", "ipv6", "add", "route", "8000::/1", g.interfaceName, "::", "publish=no"}},
		)
	}
	return commands
}

func (g *xrayTunRouteGuard) windowsDeleteRoutes() []tunRouteCommand {
	commands := make([]tunRouteCommand, 0, len(g.serverIPs)+4)
	for _, ip := range g.serverIPs {
		if ip.To4() != nil {
			commands = append(commands, tunRouteCommand{"route", []string{"delete", ip.String(), "mask", "255.255.255.255", g.gateway4}})
		} else if g.ipv6 {
			commands = append(commands, tunRouteCommand{"netsh", []string{"interface", "ipv6", "delete", "route", ip.String() + "/128", g.interfaceName}})
		}
	}
	commands = append(commands,
		tunRouteCommand{"route", []string{"delete", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0"}},
		tunRouteCommand{"route", []string{"delete", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0"}},
	)
	if g.ipv6 {
		commands = append(commands,
			tunRouteCommand{"netsh", []string{"interface", "ipv6", "delete", "route", "::/1", g.interfaceName}},
			tunRouteCommand{"netsh", []string{"interface", "ipv6", "delete", "route", "8000::/1", g.interfaceName}},
		)
	}
	return commands
}

func (g *xrayTunRouteGuard) darwinAddRoutes() []tunRouteCommand {
	commands := make([]tunRouteCommand, 0, len(g.serverIPs)+4)
	for _, ip := range g.serverIPs {
		if ip.To4() != nil {
			args := []string{"-n", "add", "-host", ip.String()}
			if g.gateway4 != "" {
				args = append(args, g.gateway4)
			} else {
				args = append(args, "-iface", g.dev4)
			}
			commands = append(commands, tunRouteCommand{"route", args})
		} else if g.ipv6 && (g.gateway6 != "" || g.dev6 != "") {
			args := []string{"-n", "add", "-inet6", "-host", ip.String()}
			if g.gateway6 != "" {
				args = append(args, g.gateway6)
			} else {
				args = append(args, "-iface", g.dev6)
			}
			commands = append(commands, tunRouteCommand{"route", args})
		}
	}
	commands = append(commands,
		tunRouteCommand{"route", []string{"-n", "add", "-net", "0.0.0.0/1", "-iface", g.interfaceName}},
		tunRouteCommand{"route", []string{"-n", "add", "-net", "128.0.0.0/1", "-iface", g.interfaceName}},
	)
	if g.ipv6 {
		commands = append(commands,
			tunRouteCommand{"route", []string{"-n", "add", "-inet6", "-net", "::/1", "-iface", g.interfaceName}},
			tunRouteCommand{"route", []string{"-n", "add", "-inet6", "-net", "8000::/1", "-iface", g.interfaceName}},
		)
	}
	return commands
}

func (g *xrayTunRouteGuard) darwinDeleteRoutes() []tunRouteCommand {
	commands := make([]tunRouteCommand, 0, len(g.serverIPs)+4)
	for _, ip := range g.serverIPs {
		if ip.To4() != nil {
			commands = append(commands, tunRouteCommand{"route", []string{"-n", "delete", "-host", ip.String()}})
		} else if g.ipv6 {
			commands = append(commands, tunRouteCommand{"route", []string{"-n", "delete", "-inet6", "-host", ip.String()}})
		}
	}
	commands = append(commands,
		tunRouteCommand{"route", []string{"-n", "delete", "-net", "0.0.0.0/1"}},
		tunRouteCommand{"route", []string{"-n", "delete", "-net", "128.0.0.0/1"}},
	)
	if g.ipv6 {
		commands = append(commands,
			tunRouteCommand{"route", []string{"-n", "delete", "-inet6", "-net", "::/1"}},
			tunRouteCommand{"route", []string{"-n", "delete", "-inet6", "-net", "8000::/1"}},
		)
	}
	return commands
}

func (g *xrayTunRouteGuard) linuxAddRoutes() []tunRouteCommand {
	commands := make([]tunRouteCommand, 0, len(g.serverIPs)+4)
	for _, ip := range g.serverIPs {
		if ip.To4() != nil {
			args := []string{"route", "add", ip.String() + "/32"}
			if g.gateway4 != "" {
				args = append(args, "via", g.gateway4)
			}
			if g.dev4 != "" {
				args = append(args, "dev", g.dev4)
			}
			commands = append(commands, tunRouteCommand{"ip", args})
		} else if g.ipv6 && (g.gateway6 != "" || g.dev6 != "") {
			args := []string{"-6", "route", "add", ip.String() + "/128"}
			if g.gateway6 != "" {
				args = append(args, "via", g.gateway6)
			}
			if g.dev6 != "" {
				args = append(args, "dev", g.dev6)
			}
			commands = append(commands, tunRouteCommand{"ip", args})
		}
	}
	commands = append(commands,
		tunRouteCommand{"ip", []string{"route", "add", "0.0.0.0/1", "dev", g.interfaceName}},
		tunRouteCommand{"ip", []string{"route", "add", "128.0.0.0/1", "dev", g.interfaceName}},
	)
	if g.ipv6 {
		commands = append(commands,
			tunRouteCommand{"ip", []string{"-6", "route", "add", "::/1", "dev", g.interfaceName}},
			tunRouteCommand{"ip", []string{"-6", "route", "add", "8000::/1", "dev", g.interfaceName}},
		)
	}
	return commands
}

func (g *xrayTunRouteGuard) linuxDeleteRoutes() []tunRouteCommand {
	commands := make([]tunRouteCommand, 0, len(g.serverIPs)+4)
	for _, ip := range g.serverIPs {
		if ip.To4() != nil {
			commands = append(commands, tunRouteCommand{"ip", []string{"route", "del", ip.String() + "/32"}})
		} else if g.ipv6 {
			commands = append(commands, tunRouteCommand{"ip", []string{"-6", "route", "del", ip.String() + "/128"}})
		}
	}
	commands = append(commands,
		tunRouteCommand{"ip", []string{"route", "del", "0.0.0.0/1"}},
		tunRouteCommand{"ip", []string{"route", "del", "128.0.0.0/1"}},
	)
	if g.ipv6 {
		commands = append(commands,
			tunRouteCommand{"ip", []string{"-6", "route", "del", "::/1"}},
			tunRouteCommand{"ip", []string{"-6", "route", "del", "8000::/1"}},
		)
	}
	return commands
}

func (g *xrayTunRouteGuard) waitForInterface(ctx context.Context) error {
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for {
		if err := g.interfaceReady(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface %q did not become ready: %w", g.interfaceName, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (g *xrayTunRouteGuard) interfaceReady(ctx context.Context) error {
	switch g.platform {
	case "windows":
		_, err := g.windowsInterfaceIndex(ctx)
		return err
	case "darwin":
		_, err := g.runner(ctx, "ifconfig", g.interfaceName)
		return err
	case "linux":
		_, err := g.runner(ctx, "ip", "link", "show", "dev", g.interfaceName)
		return err
	default:
		return fmt.Errorf("unsupported TUN platform %s", g.platform)
	}
}

func (g *xrayTunRouteGuard) windowsInterfaceIndex(ctx context.Context) (string, error) {
	output, err := g.runner(ctx, "route", "print")
	if err == nil {
		if index := parseWindowsRouteInterfaceIndex(output, g.interfaceName); index != "" {
			return index, nil
		}
	}

	netshOutput, netshErr := g.runner(ctx, "netsh", "interface", "ipv4", "show", "interfaces")
	if netshErr == nil {
		if index := parseWindowsRouteInterfaceIndex(netshOutput, g.interfaceName); index != "" {
			return index, nil
		}
	}
	if err != nil {
		return "", err
	}
	if netshErr != nil {
		return "", netshErr
	}
	return "", fmt.Errorf("Windows TUN interface %q was not found in route print or netsh interface output", g.interfaceName)
}

func (g *xrayTunRouteGuard) runRouteMutation(ctx context.Context, command tunRouteCommand) error {
	if command.Name == "" {
		return nil
	}
	if g.platform == "windows" {
		command = normalizeWindowsRouteDelete(command)
	}
	output, err := g.runner(ctx, command.Name, command.Args...)
	if err == nil {
		return nil
	}
	if g.platform == "windows" && routeMutationNeedsElevation(output, err) {
		output, err = g.runner(ctx, "powershell", "-NoProfile", "-Command", windowsElevatedRouteCommand(command))
		return routeCommandError(command, output, err)
	}
	if g.platform == "darwin" {
		output, err = g.runner(ctx, "osascript", "-e", "do shell script "+strconv.Quote(shellJoin(append([]string{command.Name}, command.Args...)...))+" with administrator privileges")
		return routeCommandError(command, output, err)
	}
	if g.platform == "linux" {
		output, err = g.runner(ctx, "pkexec", "sh", "-c", shellJoin(append([]string{command.Name}, command.Args...)...))
		return routeCommandError(command, output, err)
	}
	return routeCommandError(command, output, err)
}

func normalizeWindowsRouteDelete(command tunRouteCommand) tunRouteCommand {
	if !strings.EqualFold(command.Name, "route") || len(command.Args) != 2 || !strings.EqualFold(command.Args[0], "delete") {
		return command
	}
	switch command.Args[1] {
	case "0.0.0.0", "128.0.0.0":
		command.Args = []string{"delete", command.Args[1], "mask", "128.0.0.0", "0.0.0.0"}
	}
	return command
}

func routeCommandError(command tunRouteCommand, output string, err error) error {
	if err == nil {
		return nil
	}
	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("%s %s failed: %w", command.Name, strings.Join(command.Args, " "), err)
	}
	return fmt.Errorf("%s %s failed: %w: %s", command.Name, strings.Join(command.Args, " "), err, strings.TrimSpace(output))
}

func routeMutationNeedsElevation(output string, err error) bool {
	text := strings.ToLower(output + " " + err.Error())
	return strings.Contains(text, "access is denied") ||
		strings.Contains(text, "requires elevation") ||
		strings.Contains(text, "administrator")
}

func resolveTunServerIPs(ctx context.Context, host string, includeIPv6 bool) ([]net.IP, error) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return nil, errors.New("V2Ray server host is required for TUN route bypass")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil && !includeIPv6 {
			return nil, fmt.Errorf("V2Ray server %s is IPv6 but TUN IPv6 is disabled", host)
		}
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve V2Ray server for TUN bypass routes: %w", err)
	}
	seen := map[string]struct{}{}
	var ips []net.IP
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			continue
		}
		if ip.To4() == nil && !includeIPv6 {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("V2Ray server %s resolved to no usable IP addresses for TUN routes", host)
	}
	return ips, nil
}

func windowsDefaultGateway(ctx context.Context, runner SystemProxyCommandRunner, family string) (string, error) {
	prefix := "0.0.0.0/0"
	if family == "IPv6" {
		prefix = "::/0"
	}
	output, err := runner(ctx, "powershell", "-NoProfile", "-Command", "(Get-NetRoute -AddressFamily "+family+" -DestinationPrefix '"+prefix+"' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).NextHop")
	if err != nil {
		return "", err
	}
	gateway := strings.TrimSpace(output)
	if gateway == "" || gateway == "0.0.0.0" || gateway == "::" {
		return "", fmt.Errorf("default %s gateway not found", family)
	}
	return gateway, nil
}

func parseDarwinDefaultRoute(output string) (gateway string, iface string) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "gateway":
			gateway = strings.TrimSpace(value)
		case "interface":
			iface = strings.TrimSpace(value)
		}
	}
	return gateway, iface
}

func parseLinuxDefaultRoute(output string) (gateway string, iface string) {
	fields := strings.Fields(output)
	for idx := 0; idx < len(fields)-1; idx++ {
		switch fields[idx] {
		case "via":
			gateway = fields[idx+1]
		case "dev":
			iface = fields[idx+1]
		}
	}
	return gateway, iface
}

func parseWindowsRouteInterfaceIndex(output string, interfaceName string) string {
	name := strings.ToLower(strings.TrimSpace(interfaceName))
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(trimmed), name) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		index, _, _ := strings.Cut(fields[0], "...")
		if _, err := strconv.Atoi(index); err == nil {
			return index
		}
	}
	return ""
}

func windowsElevatedRouteCommand(command tunRouteCommand) string {
	quotedArgs := make([]string, 0, len(command.Args))
	for _, arg := range command.Args {
		quotedArgs = append(quotedArgs, powershellSingleQuote(arg))
	}
	return "$p=Start-Process -FilePath " + powershellSingleQuote(command.Name) +
		" -ArgumentList @(" + strings.Join(quotedArgs, ",") + ") -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode"
}

func shellJoin(parts ...string) string {
	quoted := make([]string, 0, len(parts))
	for _, part := range parts {
		quoted = append(quoted, shellQuote(part))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func benignRouteDeleteError(err error) bool {
	if err == nil {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not in table") ||
		strings.Contains(text, "not found") ||
		strings.Contains(text, "cannot find") ||
		strings.Contains(text, "element not found") ||
		strings.Contains(text, "no such process") ||
		strings.Contains(text, "no such file")
}

func ensureWintunDLL(binaryPath string, searchDirs []string) error {
	if strings.TrimSpace(binaryPath) == "" {
		return errors.New("xray binary path is required for Wintun setup")
	}
	dest := filepath.Join(filepath.Dir(binaryPath), "wintun.dll")
	if isRegularFile(dest) {
		return nil
	}
	for _, dir := range append([]string{filepath.Dir(binaryPath)}, searchDirs...) {
		candidate := filepath.Join(dir, "wintun.dll")
		if !isRegularFile(candidate) {
			continue
		}
		raw, err := os.ReadFile(candidate)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, raw, 0o755); err != nil {
			return fmt.Errorf("failed to copy wintun.dll next to xray.exe: %w", err)
		}
		return nil
	}
	return errors.New("wintun.dll is required for Xray TUN mode on Windows; place it next to xray.exe or in the cores folder")
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func defaultTunInterfaceName(platform string) string {
	switch platform {
	case "windows":
		return "WhiteDNS Tunnel"
	case "darwin":
		return "utun20"
	default:
		return "xray0"
	}
}

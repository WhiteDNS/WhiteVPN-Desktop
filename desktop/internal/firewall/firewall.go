package firewall

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"whitevpn-desktop/internal/model"
)

const EnabledMessage = "Firewall is on. WhiteDNS may need local proxy/DNS traffic allowed."

type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

func Detect(ctx context.Context) model.FirewallStatus {
	return detect(ctx, runtime.GOOS, runCommand)
}

func detect(ctx context.Context, goos string, runner CommandRunner) model.FirewallStatus {
	if ctx == nil {
		ctx = context.Background()
	}
	if runner == nil {
		runner = runCommand
	}

	switch goos {
	case "darwin":
		return detectMacOS(ctx, runner)
	case "windows":
		return detectWindows(ctx, runner)
	case "linux":
		return detectLinux(ctx, runner)
	default:
		return unsupported("System firewall")
	}
}

func detectMacOS(ctx context.Context, runner CommandRunner) model.FirewallStatus {
	output, err := runner(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil && strings.TrimSpace(output) == "" {
		return unsupported("macOS Application Firewall")
	}
	if enabled, ok := parseMacOSFirewallStatus(output); ok {
		return status("macOS Application Firewall", enabled)
	}
	return unsupported("macOS Application Firewall")
}

func detectWindows(ctx context.Context, runner CommandRunner) model.FirewallStatus {
	output, err := runner(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil && strings.TrimSpace(output) == "" {
		return unsupported("Windows Defender Firewall")
	}
	if enabled, ok := parseWindowsFirewallStatus(output); ok {
		return status("Windows Defender Firewall", enabled)
	}
	return unsupported("Windows Defender Firewall")
}

func detectLinux(ctx context.Context, runner CommandRunner) model.FirewallStatus {
	var disabled *model.FirewallStatus

	if output, err := runner(ctx, "ufw", "status"); err == nil || strings.TrimSpace(output) != "" {
		if enabled, ok := parseUFWStatus(output); ok {
			next := status("ufw", enabled)
			if enabled {
				return next
			}
			disabled = &next
		}
	}

	if output, err := runner(ctx, "firewall-cmd", "--state"); err == nil || strings.TrimSpace(output) != "" {
		if enabled, ok := parseFirewalldStatus(output); ok {
			next := status("firewalld", enabled)
			if enabled {
				return next
			}
			if disabled == nil {
				disabled = &next
			}
		}
	}

	if disabled != nil {
		return *disabled
	}
	return unsupported("Linux firewall")
}

func parseMacOSFirewallStatus(output string) (bool, bool) {
	normalized := strings.ToLower(output)
	switch {
	case strings.Contains(normalized, "state = 1") || strings.Contains(normalized, "firewall is enabled"):
		return true, true
	case strings.Contains(normalized, "state = 0") || strings.Contains(normalized, "firewall is disabled"):
		return false, true
	default:
		return false, false
	}
}

func parseWindowsFirewallStatus(output string) (bool, bool) {
	seen := false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(line)))
		if len(fields) < 2 || fields[0] != "state" {
			continue
		}
		seen = true
		if fields[1] == "on" {
			return true, true
		}
	}
	return false, seen
}

func parseUFWStatus(output string) (bool, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(line, "status:") {
			continue
		}
		switch {
		case strings.Contains(line, "inactive"):
			return false, true
		case strings.Contains(line, "active"):
			return true, true
		default:
			return false, false
		}
	}
	return false, false
}

func parseFirewalldStatus(output string) (bool, bool) {
	normalized := strings.ToLower(strings.TrimSpace(output))
	switch normalized {
	case "running":
		return true, true
	case "not running":
		return false, true
	default:
		return false, false
	}
}

func status(name string, enabled bool) model.FirewallStatus {
	message := "Firewall is off."
	if enabled {
		message = EnabledMessage
	}
	return model.FirewallStatus{
		Enabled:   enabled,
		Supported: true,
		Name:      name,
		Message:   message,
	}
}

func unsupported(name string) model.FirewallStatus {
	return model.FirewallStatus{
		Supported: false,
		Name:      name,
	}
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(commandCtx, name, args...)
	hideConsoleWindow(cmd)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

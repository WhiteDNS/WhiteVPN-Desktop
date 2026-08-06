//go:build windows

package session

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func verifyTunnel(device string, ipv6 bool) error {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("adapter %q is missing: %w", device, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("adapter %q is down", device)
	}

	output, err := tunnelRoutes(device)
	if err != nil {
		return err
	}
	return verifyTunnelRoutes(output, ipv6 && hasRoutableIPv6(device))
}

// tunnelRoutes lists the destination prefixes routed through the adapter.
//
// Get-NetRoute is the only way to ask Windows this without binding to the IP
// Helper API, but PowerShell is not something to depend on lightly: it is slow
// to start, a machine can have its execution policy locked down, and on some
// systems powershell.exe is not on PATH at all. So a failure to run it is
// reported as its own thing rather than as a broken tunnel — the difference
// matters to whoever reads the report.
func tunnelRoutes(device string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shell, err := exec.LookPath("powershell.exe")
	if err != nil {
		if system := os.Getenv("SystemRoot"); system != "" {
			shell = system + `\System32\WindowsPowerShell\v1.0\powershell.exe`
		} else {
			return "", fmt.Errorf("%w: powershell is not available to read the adapter's routes", errTunnelUnverifiable)
		}
	}

	// The device name goes through the environment rather than into the command
	// text, so a name carrying a quote cannot become part of the script.
	command := exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive", "-Command",
		`$ErrorActionPreference='SilentlyContinue'; Get-NetRoute -InterfaceAlias $env:WHITEVPN_TUN_DEVICE | ForEach-Object { $_.DestinationPrefix }`)
	command.Env = append(os.Environ(), "WHITEVPN_TUN_DEVICE="+device)

	out, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read routes for %q: %w: %s", device, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

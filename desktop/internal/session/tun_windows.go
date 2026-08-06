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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$ErrorActionPreference='Stop'; Get-NetRoute -InterfaceAlias $env:WHITEVPN_TUN_DEVICE | ForEach-Object { $_.DestinationPrefix }`)
	command.Env = append(os.Environ(), "WHITEVPN_TUN_DEVICE="+device)
	out, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("read routes for %q: %w: %s", device, err, strings.TrimSpace(string(out)))
	}
	return verifyTunnelRoutes(string(out), ipv6)
}

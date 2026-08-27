//go:build linux

package session

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Verifying the tunnel on Linux cannot read routes the way Windows does.
//
// tunnelRoutes on Windows asks Get-NetRoute for every prefix attached to the
// adapter, because on Windows that is where the routing decision lives. mihomo's
// Linux tunnel does not necessarily attach its routes to the device that way —
// StrictRoute is implemented there through "unreachable policy rules" (see the
// comment on TunOptions), which means the kernel's routing decision for a given
// destination can depend on a separate table and rule chain that a plain
// `ip route show dev tun0` would not show at all.
//
// So this asks a different question, one that is correct regardless of which
// mechanism installed the routes: `ip route get <destination>` resolves policy
// routing exactly the way a real packet would and reports which interface it
// would leave through. That is what verifyTunnel actually needs to know, and it
// is the same command a person troubleshooting this by hand would reach for.
func verifyTunnel(device string, ipv6 bool) error {
	if err := verifyRouteThrough(device, "ip", "1.1.1.1"); err != nil {
		return fmt.Errorf("the tunnel has no route covering IPv4 traffic: %w", err)
	}
	if ipv6 && hasRoutableIPv6(device) {
		if err := verifyRouteThrough(device, "ip", "-6", "2606:4700:4700::1111"); err != nil {
			return fmt.Errorf("the tunnel has no route covering IPv6 traffic, which would leave this machine's IPv6 outside it: %w", err)
		}
	}
	return nil
}

// verifyRouteThrough runs `ip route get` and confirms the answer names device.
//
// args carries the address-family flag (-6) ahead of the destination, since
// that is where `ip` wants it and callers only ever pass through one of the two
// shapes above.
func verifyRouteThrough(device, ipPath string, args ...string) error {
	full, err := exec.LookPath(ipPath)
	if err != nil {
		// Not the tunnel's fault, and not evidence against it: a machine
		// without iproute2's `ip` cannot be asked, the same way a Windows
		// machine without powershell.exe cannot be. Refusing to connect over a
		// missing diagnostic tool would make the tunnel unusable somewhere it
		// might work perfectly well.
		return fmt.Errorf("%w: iproute2's ip is not available to read routing decisions", errTunnelUnverifiable)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, full, append([]string{"route", "get"}, args...)...)
	out, err := command.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("ip route get %s: %w: %s", strings.Join(args, " "), err, output)
	}

	got := routeDevice(output)
	if got == "" {
		return fmt.Errorf("could not read which interface the route uses: %s", output)
	}
	if got != device {
		return fmt.Errorf("traffic leaves through %q, not the tunnel: %s", got, output)
	}
	return nil
}

// routeDevice pulls the interface name out of `ip route get`'s answer.
//
// The line is space-separated keyword/value pairs — destination, then some
// subset of "via GATEWAY", "dev IFACE", "src ADDRESS", "uid N" — followed on its
// own line by a "cache" report this does not need. Only the first line and only
// the token after "dev" matter here.
func routeDevice(output string) string {
	firstLine, _, _ := strings.Cut(output, "\n")
	fields := strings.Fields(firstLine)
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

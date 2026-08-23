//go:build linux

package session

import (
	"fmt"
	"net"
	"os"

	"whitevpn-desktop/internal/routeparse"
)

// The adapter cannot be judged by asking the desktop about it — desktop
// commands localise their output and their absence proves nothing. The kernel
// keeps two plain tables instead, and this reads them directly: whether the
// interface exists and is up, and whether its routes really cover everything
// the tunnel claims to carry.
//
// This replaces an earlier answer of "unverifiable" on every non-Windows
// platform, which let a connection stand while saying nothing had been checked.
func verifyTunnel(device string, ipv6 bool) error {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("adapter %q is missing: %w", device, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("adapter %q is down", device)
	}

	v4raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return fmt.Errorf("%w: /proc/net/route is unreadable (%v)", errTunnelUnverifiable, err)
	}
	routes, err := routeparse.ParseIPv4(string(v4raw))
	if err != nil {
		return fmt.Errorf("%w: %v", errTunnelUnverifiable, err)
	}
	// No IPv6 table means no IPv6 at all, which has nothing to cover.
	if raw, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		routes = append(routes, routeparse.ParseIPv6(string(raw))...)
	}

	return routeparse.Covers(routes, device, ipv6 && hasRoutableIPv6(device))
}

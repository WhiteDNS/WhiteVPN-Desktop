package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// How long the tunnel is given to appear, and how often it is looked for.
//
// The adapter is not there when the engine reports success. startListener
// returns once the core is running; creating the tunnel adapter, bringing it up
// and installing its routes happens after that, and on a cold machine — the
// driver loading for the first time, a slow disk, an antivirus inspecting a new
// network adapter — it takes seconds. The check used to run once, immediately,
// and a machine that was merely slow was told its tunnel had failed.
//
// This is also why the failure was reported as "connects in proxy mode but not
// in tunnel mode": the proxy port is up straight away, so the request that
// proves the connection works passes long before the adapter exists.
const (
	tunnelBudget = 20 * time.Second
	// A second rather than half of one. Reading the adapter's routes on Windows
	// costs a PowerShell process, and forty of them across a connect is a lot of
	// work to ask for — the adapter is either there within a second or two of
	// coming up, or it is not coming.
	tunnelPollInterval = time.Second
)

// errTunnelUnverifiable means this platform has no way to inspect the adapter,
// not that the adapter is broken. The two must not be confused: refusing to
// connect because verification is unimplemented would make the tunnel unusable
// on a platform where it may work perfectly well.
var errTunnelUnverifiable = errors.New("the tunnel cannot be verified on this platform")

// waitForTunnel returns once the tunnel adapter is up and carrying routes, or
// once the budget is spent.
func waitForTunnel(ctx context.Context, device string, ipv6 bool) error {
	deadline, cancel := context.WithTimeout(ctx, tunnelBudget)
	defer cancel()

	var lastErr error
	for {
		err := verifyTunnel(device, ipv6)
		if err == nil || errors.Is(err, errTunnelUnverifiable) {
			return err
		}
		lastErr = err

		select {
		case <-deadline.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("the tunnel did not come up within %s: %w", tunnelBudget, lastErr)
		case <-time.After(tunnelPollInterval):
		}
	}
}

// verifyTunnelRoutes checks that the adapter's routes cover the traffic the
// tunnel is supposed to carry.
//
// requireIPv6 is deliberately separate from "IPv6 is switched on in the config":
// the requirement only applies to a machine that actually has IPv6. Where it is
// switched off — which plenty of users have done by hand, following one guide or
// another — the engine installs no IPv6 routes because there is no IPv6 traffic
// to carry, and demanding them refused a tunnel that was working. Where the
// machine does have IPv6, missing routes mean that traffic is leaving outside
// the tunnel, and that is worth refusing over.
func verifyTunnelRoutes(output string, requireIPv6 bool) error {
	routes := make(map[string]bool)
	for _, route := range strings.Fields(output) {
		routes[strings.ToLower(route)] = true
	}
	if !routes["0.0.0.0/0"] && !(routes["0.0.0.0/1"] && routes["128.0.0.0/1"]) {
		return fmt.Errorf("the tunnel has no route covering IPv4 traffic")
	}
	if requireIPv6 && !routes["::/0"] && !(routes["::/1"] && routes["8000::/1"]) {
		return fmt.Errorf("the tunnel has no route covering IPv6 traffic, which would leave this machine's IPv6 outside it")
	}
	return nil
}

// hasRoutableIPv6 reports whether this machine has an IPv6 address that could
// carry traffic off it.
//
// The tunnel adapter is skipped, and so are addresses that go nowhere: loopback,
// link-local, and unique-local — including the tunnel's own fd00::/8 address,
// which would otherwise make every machine look like it had IPv6 and bring back
// exactly the check this is meant to qualify.
func hasRoutableIPv6(tunnelDevice string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		// Unknown, so assume the strict case rather than waive the check.
		return true
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.EqualFold(iface.Name, tunnelDevice) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok || network.IP.To4() != nil {
				continue
			}
			ip := network.IP
			if ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
				return true
			}
		}
	}
	return false
}

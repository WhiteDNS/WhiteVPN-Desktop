//go:build darwin

package session

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/route"

	"whitevpn-desktop/internal/routeparse"
)

func ipOf4(a *route.Inet4Addr) netip.Addr { return netip.AddrFrom4(a.IP) }

func ipOf6(a *route.Inet6Addr) netip.Addr { return netip.AddrFrom16(a.IP) }

// macOS assigns uton indices at creation time — the kernel may hand back
// utun7 when the configuration asked for something else entirely — so the
// configured device name is treated as a hint and never as an answer. What is
// authoritative is the routing table: whichever interface actually carries
// this machine's default routes is the tunnel, whatever it ended up being
// called.
//
// The table comes from sysctl through x/net/route, not from `netstat`, whose
// output is localised prose.

func verifyTunnel(device string, ipv6 bool) error {
	msgs, err := routingTable()
	if err != nil {
		return fmt.Errorf("%w: %v", errTunnelUnverifiable, err)
	}
	routes := ribRoutes(msgs)

	carrier := defaultCarrier(routes)
	if carrier == "" {
		return fmt.Errorf("no interface carries a default route, so no tunnel can be carrying traffic")
	}

	iface, err := net.InterfaceByName(carrier)
	if err != nil || iface == nil {
		return fmt.Errorf("the interface carrying the tunnel's routes (%s) cannot be inspected", carrier)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("adapter %q is down", carrier)
	}

	return routeparse.Covers(routes, carrier, ipv6 && hasRoutableIPv6(carrier))
}

// defaultCarrier names the interface whose routes cover IPv4 — preferring one
// of the kernel's own tunnel interfaces, since those are what mihomo creates.
func defaultCarrier(routes []routeparse.Route) string {
	for _, r := range routes {
		if strings.HasPrefix(r.Iface, "utun") && coversIPv4(routes, r.Iface) {
			return r.Iface
		}
	}
	for _, r := range routes {
		if coversIPv4(routes, r.Iface) && looksVirtual(r.Iface) {
			return r.Iface
		}
	}
	return ""
}

func coversIPv4(routes []routeparse.Route, iface string) bool {
	return routeparse.Covers(routes, iface, false) == nil
}

func looksVirtual(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"utun", "tun", "tap", "wg"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func routingTable() ([]route.Message, error) {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	return route.ParseRIB(route.RIBTypeRoute, rib)
}

// ribRoutes turns routing-table messages into plain prefixes with their
// interface names. Messages without both a destination and a resolvable
// interface are skipped rather than fatal: the table carries plenty that this
// check does not need, and one odd entry must never hide the default beside it.
func ribRoutes(msgs []route.Message) []routeparse.Route {
	var routes []routeparse.Route
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok || len(rm.Addrs) < 1 {
			continue
		}
		name, ok := interfaceName(rm.Index)
		if !ok {
			continue
		}
		switch dst := rm.Addrs[0].(type) {
		case *route.Inet4Addr:
			bits := prefixBits(rm.Addrs, 4)
			prefix, err := ipOf4(dst).Prefix(bits)
			if err != nil {
				continue
			}
			routes = append(routes, routeparse.Route{Prefix: prefix.Masked(), Iface: name})
		case *route.Inet6Addr:
			bits := prefixBits(rm.Addrs, 16)
			prefix, err := (ipOf6(dst)).Prefix(bits)
			if err != nil {
				continue
			}
			routes = append(routes, routeparse.Route{Prefix: prefix.Masked(), Iface: name})
		}
	}
	return routes
}

func interfaceName(index int) (string, bool) {
	iface, err := net.InterfaceByIndex(index)
	if err != nil || iface == nil {
		return "", false
	}
	return iface.Name, true
}

// prefixBits reads the netmask out of the addresses attached to a message.
// A missing mask means a host route or a full default depending on the
// destination; treating it as "exactly the destination" is right for both.
func prefixBits(addrs []route.Addr, family int) int {
	mask, ok := addrs[2].(*route.Inet4Addr)
	if family == 4 && ok {
		return countBits(mask.IP[:])
	}
	if mask6, ok := addrs[2].(*route.Inet6Addr); family == 16 && ok {
		return countBits(mask6.IP[:])
	}
	if family == 4 {
		return 32
	}
	return 128
}

func countBits(b []byte) int {
	bits := 0
	for _, byteValue := range b {
		for v := byteValue; v != 0; v >>= 1 {
			bits += int(v & 1)
		}
	}
	return bits
}

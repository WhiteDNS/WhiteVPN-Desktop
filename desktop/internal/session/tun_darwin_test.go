//go:build darwin

package session

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/route"

	"whitevpn-desktop/internal/routeparse"
)

func mustMsg(t *testing.T, ifaceIndex int, dst netip.Addr, bits int) *route.RouteMessage {
	t.Helper()
	msg := &route.RouteMessage{Index: ifaceIndex, Addrs: make([]route.Addr, 3)}
	if dst.Is4() {
		ip4 := dst.As4()
		msg.Addrs[0] = &route.Inet4Addr{IP: ip4}
		mask := net.CIDRMask(bits, 32)
		var m [4]byte
		copy(m[:], mask)
		msg.Addrs[2] = &route.Inet4Addr{IP: m}
		return msg
	}
	ip6 := dst.As16()
	msg.Addrs[0] = &route.Inet6Addr{IP: ip6}
	mask := net.CIDRMask(bits, 128)
	var m [16]byte
	copy(m[:], mask)
	msg.Addrs[2] = &route.Inet6Addr{IP: m}
	return msg
}

// The utun the kernel actually created is whatever the table says it is — this
// is the check that refuses to trust a configured name.
func TestRibRoutesReadsHandBuiltTable(t *testing.T) {
	iface := testInterface(t) // a real interface index on this machine

	msgs := []route.Message{
		mustMsg(t, iface.Index, netip.MustParseAddr("0.0.0.0"), 0), // default v4 via utun
		mustMsg(t, iface.Index, netip.MustParseAddr("::"), 0),      // default v6 via utun
		mustMsg(t, 1, netip.MustParseAddr("192.168.1.0"), 24),      // physical LAN (lo index)
	}
	routes := ribRoutes(msgs)
	if len(routes) != 3 {
		t.Fatalf("parsed %d routes, want 3: %+v", len(routes), routes)
	}

	carrier := defaultCarrier(routes)
	if carrier != iface.Name {
		t.Fatalf("carrier = %q, want %q", carrier, iface.Name)
	}
	if err := routeparse.Covers(routes, carrier, true); err != nil {
		t.Fatalf("full defaults on both families must pass: %v", err)
	}

	// Drop the v6 default: with IPv6 required, containment has failed.
	halved := routes[:1]
	if err := routeparse.Covers(halved, carrier, true); err == nil {
		t.Fatal("missing IPv6 coverage must fail when required")
	}

	// No utun in the table at all — the tunnel never came up.
	routes = ribRoutes(msgs[2:])
	if carrier := defaultCarrier(routes); carrier != "" || coversIPv4(routes, "lo0") && looksVirtual("lo0") {
		t.Fatalf("a table without virtual interfaces must name no carrier, got %q", carrier)
	}
}

func TestSplitHalvesCountAsCoverage(t *testing.T) {
	iface := testInterface(t)
	msgs := []route.Message{
		mustMsg(t, iface.Index, netip.MustParseAddr("0.0.0.0"), 1),
		mustMsg(t, iface.Index, netip.MustParseAddr("128.0.0.0"), 1),
	}
	routes := ribRoutes(msgs)
	if err := routeparse.Covers(routes, iface.Name, false); err != nil {
		t.Fatalf("the split-default shape must verify: %v", err)
	}
}

// testInterface returns a real interface index on this machine so parsed
// messages resolve to a name the way the live path does. A kernel tunnel is
// preferred because that is what the discovery rules look for.
func testInterface(t *testing.T) *net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no interfaces to work with")
	}
	for i := range ifaces {
		if strings.HasPrefix(ifaces[i].Name, "utun") {
			return &ifaces[i]
		}
	}
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback == 0 {
			return &ifaces[i]
		}
	}
	t.Skip("only loopback here")
	return nil
}

func TestLiveRoutingTableParsesOnThisMachine(t *testing.T) {
	msgs, err := routingTable()
	if err != nil {
		t.Skipf("no routing table available: %v", err)
	}
	routes := ribRoutes(msgs)
	if len(routes) == 0 {
		t.Fatal("a live macOS machine always has routes")
	}
	t.Logf("%d live routes parsed; default carrier: %q", len(routes), defaultCarrier(routes))
}

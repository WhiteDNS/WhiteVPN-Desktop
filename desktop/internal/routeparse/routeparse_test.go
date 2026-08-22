package routeparse

import (
	"net/netip"
	"strings"
	"testing"
)

// A default route and the split halves, as a Linux kernel writes them: the
// destination word is little-endian hex, which is why 10.0.0.0 shows up as
// 0000000A and why nobody should ever hand-write this parser twice.
const procNetRoute = `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
tun_wp	00000000	00000000	0003	0	0	0	00000000	0	0	0
eth0	00000000	0100A8C0	0003	0	0	100	00008000	0	0	0
eth0	0000A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`

func TestParseIPv4FindsDefaultAndHalves(t *testing.T) {
	routes, err := ParseIPv4(procNetRoute)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 {
		t.Fatalf("got %d routes, want 3: %+v", len(routes), routes)
	}
	if routes[2].Prefix.String() != "192.168.0.0/24" || routes[2].Iface != "eth0" {
		t.Fatalf("subnet route parsed wrong: %+v", routes[2])
	}
	if routes[0].Prefix.String() != "0.0.0.0/0" || routes[0].Iface != "tun_wp" {
		t.Fatalf("default route parsed wrong: %+v", routes[0])
	}
	// Mask 00008000 read little-endian is 00800000 → /1, which is what a split
	// default's first half looks like.
	if routes[1].Prefix.String() != "0.0.0.0/1" || routes[1].Iface != "eth0" {
		t.Fatalf("first half parsed wrong: %+v", routes[1])
	}
}

func TestParseIPv4RejectsGarbage(t *testing.T) {
	if _, err := ParseIPv4("not a route table"); err == nil {
		t.Fatal("expected garbage to be refused, not silently emptied")
	}
}

func TestCoversAcceptsFullDefault(t *testing.T) {
	routes, err := ParseIPv4(procNetRoute)
	if err != nil {
		t.Fatal(err)
	}
	if err := Covers(routes, "tun_wp", false); err != nil {
		t.Fatalf("a full default must satisfy IPv4 coverage: %v", err)
	}
}

func TestCoversRefusesTunnelWithoutRoutes(t *testing.T) {
	routes, _ := ParseIPv4(procNetRoute)
	err := Covers(routes, "wg0", false)
	if err == nil {
		t.Fatal("an interface carrying no IPv4 route must fail verification")
	}
	want := "the tunnel has no route covering IPv4 traffic"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err, want)
	}
}

func TestCoversAcceptsSplitHalves(t *testing.T) {
	routes := []Route{
		{mustPrefix(t, "0.0.0.0/1"), "WhiteVPN"},
		{mustPrefix(t, "128.0.0.0/1"), "whitevpn"},
	}
	err := Covers(routes, "WHITEVPN", true)
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("halves must satisfy IPv4 (case-insensitive name), leaving only IPv6 to complain about: %v", err)
	}
}

func TestCoversIgnoresOtherInterfaces(t *testing.T) {
	// The physical adapter's own default does not cover for the tunnel: the
	// check exists precisely because traffic can leave outside it.
	routes := []Route{{mustPrefix(t, "0.0.0.0/0"), "eth0"}}
	if err := Covers(routes, "WhiteVPN", false); err == nil {
		t.Fatal("another interface's default route must not count as tunnel coverage")
	}
}

func TestCoversIPv6Requirement(t *testing.T) {
	routes := []Route{{mustPrefix(t, "0.0.0.0/0"), "WhiteVPN"}}
	if err := Covers(routes, "WhiteVPN", false); err != nil {
		t.Fatalf("IPv6 waived when not required: %v", err)
	}
	if err := Covers(routes, "WhiteVPN", true); err == nil {
		t.Fatal("required IPv6 with no v6 routes must fail")
	}

	withV6 := append(routes, Route{mustPrefix(t, "::/0"), "WhiteVPN"})
	if err := Covers(withV6, "WhiteVPN", true); err != nil {
		t.Fatalf("full v6 default must pass: %v", err)
	}

	halved := []Route{
		{mustPrefix(t, "0.0.0.0/0"), "WhiteVPN"},
		{mustPrefix(t, "::/1"), "WhiteVPN"},
		{mustPrefix(t, "8000::/1"), "WhiteVPN"},
	}
	if err := Covers(halved, "WhiteVPN", true); err != nil {
		t.Fatalf("split v6 halves must pass: %v", err)
	}
}

func TestParseIPv6(t *testing.T) {
	// Columns per line: destination, prefix length, next hop, scope, interface.
	const table = `
00000000000000000000000000000000 00 00000000000000000000000000000000 00 tun_wp 00000001000000000000000000000000 ffffffffffffffff 00000000
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 eth0 00000001000000000000000000000000 ffffffffffffffff 00000000
garbage line
`
	routes := ParseIPv6(table)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2 (the malformed line is skipped): %+v", len(routes), routes)
	}
	if routes[0].Prefix.String() != "::/0" || routes[0].Iface != "tun_wp" {
		t.Fatalf("default v6 route parsed wrong: %+v", routes[0])
	}
	if routes[1].Prefix.String() != "fe80::/40" {
		t.Fatalf("prefix parsed wrong: %+v", routes[1])
	}
}

func TestParseIPv6EmptyMeansNoIPv6(t *testing.T) {
	if routes := ParseIPv6(""); len(routes) != 0 {
		t.Fatalf("an empty table parses to nothing, got %+v", routes)
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return prefix.Masked()
}

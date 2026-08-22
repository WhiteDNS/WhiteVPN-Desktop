// Package routeparse reads the kernel's own route tables without running a
// desktop command or parsing output meant for a human.
//
// Localised `ip route` output is exactly how a verification step ends up
// believing a German machine has no default gateway. /proc/net/route and
// /proc/net/ipv6_route are kernel interfaces: stable, untranslated, and present
// wherever there is a kernel. They are also plain text, which makes every part
// of this package testable on any development machine.
package routeparse

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Route is one prefix the kernel says is routed through one interface.
type Route struct {
	Prefix netip.Prefix
	Iface  string
}

// ParseIPv4 reads the content of /proc/net/route.
//
// Each line carries the destination as a little-endian hex word and the
// interface by name. The default route is destination 00000000; split routes
// installed to outrank an existing default arrive as 00000000/1 and 80000000/1,
// which is why coverage is checked against halves as well as zero.
func ParseIPv4(content string) ([]Route, error) {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "\t") {
		return nil, fmt.Errorf("routeparse: not an IPv4 kernel route table")
	}
	var routes []Route
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		dest, err := parseHexWordLE(fields[1])
		if err != nil {
			return nil, fmt.Errorf("routeparse: %w", err)
		}
		mask, err := parseHexWordLE(fields[7])
		if err != nil {
			return nil, fmt.Errorf("routeparse: %w", err)
		}
		addr := netip.AddrFrom4(dest)
		prefix, err := addr.Prefix(maskBits(mask))
		if err != nil {
			continue
		}
		routes = append(routes, Route{Prefix: prefix.Masked(), Iface: fields[0]})
	}
	return routes, nil
}

// ParseIPv6 reads the content of /proc/net/ipv6_route.
//
// There the destination and prefix length are separate columns, written as
// big-endian hex. A missing file means no IPv6 at all, which callers treat as
// "nothing to verify" rather than an error; a malformed line is skipped, since
// one odd entry (a cached route, a multipath hop) must not hide the default
// that sits beside it.
func ParseIPv6(content string) []Route {
	var routes []Route
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != 16 {
			continue
		}
		bits, err := strconv.Atoi(fields[1])
		if err != nil || bits < 0 || bits > 128 {
			continue
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		prefix, err := addr.Unmap().Prefix(bits)
		if err != nil {
			continue
		}
		routes = append(routes, Route{Prefix: prefix.Masked(), Iface: fields[4]})
	}
	return routes
}

// Covers reports whether routes carry everything an up tunnel must:
// all of IPv4, and — when required and the host can actually use it — all of
// IPv6. A full default satisfies the check, and so do the two halves, which is
// the shape mihomo installs to outrank an existing default rather than fight it.
func Covers(routes []Route, iface string, requireIPv6 bool) error {
	v4 := make(map[string]bool)
	v6 := make(map[string]bool)
	for _, r := range routes {
		if !strings.EqualFold(r.Iface, iface) {
			continue
		}
		key := r.Prefix.String()
		if r.Prefix.Addr().Is4() {
			v4[key] = true
		} else {
			v6[key] = true
		}
	}
	if !v4["0.0.0.0/0"] && !(v4["0.0.0.0/1"] && v4["128.0.0.0/1"]) {
		return fmt.Errorf("the tunnel has no route covering IPv4 traffic")
	}
	if requireIPv6 && !v6["::/0"] && !(v6["::/1"] && v6["8000::/1"]) {
		return fmt.Errorf("the tunnel has no route covering IPv6 traffic, which would leave this machine's IPv6 outside it")
	}
	return nil
}

// parseHexWordLE reads an eight-digit hex word that the kernel writes
// little-endian: the address 10.0.0.0 appears as 0000000A.
func parseHexWordLE(word string) ([4]byte, error) {
	var out [4]byte
	raw, err := hex.DecodeString(word)
	if err != nil || len(raw) != 4 {
		return out, fmt.Errorf("%q is not a kernel hex address", word)
	}
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	return out, nil
}

func maskBits(mask [4]byte) int {
	bits := 0
	for _, b := range mask {
		for b != 0 {
			bits += int(b & 1)
			b >>= 1
		}
	}
	return bits
}

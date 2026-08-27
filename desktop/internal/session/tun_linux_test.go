//go:build linux

package session

import "testing"

// Real shapes `ip route get` answers with, captured from iproute2's own
// documentation and behaviour: a gateway hop, a directly connected destination,
// and the "cache" line iproute2 appends that must not be mistaken for a second
// answer.
func TestRouteDeviceReadsTheInterfaceFromIPRouteGet(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "through a gateway, with a cache line following",
			output: "1.1.1.1 via 10.0.0.1 dev tun0 src 10.0.0.2 uid 1000 \n    cache",
			want:   "tun0",
		},
		{
			name:   "directly connected, no gateway",
			output: "192.168.1.1 dev eth0 src 192.168.1.50 uid 1000",
			want:   "eth0",
		},
		{
			name:   "IPv6",
			output: "2606:4700:4700::1111 via fe80::1 dev tun0 src 2001:db8::2 metric 1024 pref medium",
			want:   "tun0",
		},
		{
			name:   "no device token at all",
			output: "RTNETLINK answers: Network is unreachable",
			want:   "",
		},
		{
			name:   "empty",
			output: "",
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeDevice(tc.output); got != tc.want {
				t.Errorf("routeDevice(%q) = %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

// The check that matters: traffic addressed to the internet has to actually
// resolve, through whatever mechanism installed the routes, to the tunnel's own
// device — not merely to some device.
func TestVerifyRouteThroughRejectsTheWrongInterface(t *testing.T) {
	if got := routeDevice("1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.50"); got == "tun0" {
		t.Fatal("a route that leaves through the physical adapter must not read as the tunnel")
	}
}

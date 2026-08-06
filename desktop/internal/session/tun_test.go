package session

import "testing"

func TestVerifyTunnelRoutesRequiresFullIPv4AndIPv6Coverage(t *testing.T) {
	if err := verifyTunnelRoutes("0.0.0.0/1\n128.0.0.0/1\n::/1\n8000::/1\n", true); err != nil {
		t.Fatal(err)
	}
	if err := verifyTunnelRoutes("0.0.0.0/1\n::/0\n", true); err == nil {
		t.Fatal("half an IPv4 route must not be accepted")
	}
	if err := verifyTunnelRoutes("0.0.0.0/0\n", true); err == nil {
		t.Fatal("IPv6 must be covered when it is enabled")
	}
	if err := verifyTunnelRoutes("0.0.0.0/0\n", false); err != nil {
		t.Fatal(err)
	}
}

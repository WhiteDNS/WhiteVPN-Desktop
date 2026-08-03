package main

import "testing"

func TestProxyShareIPsWildcardUsesDetectedNetworkIPv4(t *testing.T) {
	localIP, publicIP := proxyShareIPs("0.0.0.0", func() string {
		return "192.168.0.106"
	})

	if localIP != "127.0.0.1" {
		t.Fatalf("expected local proxy IP, got %q", localIP)
	}
	if publicIP != "192.168.0.106" {
		t.Fatalf("expected detected public proxy IP, got %q", publicIP)
	}
}

func TestProxyShareIPsWildcardHandlesMissingNetworkIPv4(t *testing.T) {
	localIP, publicIP := proxyShareIPs("0.0.0.0", func() string {
		return ""
	})

	if localIP != "127.0.0.1" {
		t.Fatalf("expected local proxy IP, got %q", localIP)
	}
	if publicIP != "" {
		t.Fatalf("expected empty public proxy IP, got %q", publicIP)
	}
}

func TestProxyShareIPsNonWildcardKeepsSingleEndpoint(t *testing.T) {
	localIP, publicIP := proxyShareIPs("127.0.0.1", func() string {
		return "192.168.0.106"
	})

	if localIP != "" || publicIP != "" {
		t.Fatalf("expected no display split for non-wildcard bind, got local=%q public=%q", localIP, publicIP)
	}
}

func TestChooseShareNetworkIPv4PrefersActiveRoute(t *testing.T) {
	got := chooseShareNetworkIPv4(
		func() string { return "10.0.0.8" },
		func() string { return "192.168.0.106" },
	)

	if got != "10.0.0.8" {
		t.Fatalf("expected active route IP, got %q", got)
	}
}

func TestChooseShareNetworkIPv4FallsBackToPrivateInterface(t *testing.T) {
	got := chooseShareNetworkIPv4(
		func() string { return "127.0.0.1" },
		func() string { return "192.168.0.106" },
	)

	if got != "192.168.0.106" {
		t.Fatalf("expected fallback private interface IP, got %q", got)
	}
}

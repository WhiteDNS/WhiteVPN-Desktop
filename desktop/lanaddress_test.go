package main

import (
	"net"
	"testing"
)

// A wrong address here is worse than none: it sends somebody to configure a
// device with a number that cannot work, and the failure looks like the VPN's.
func TestTheSharedAddressIsOneAnotherDeviceCouldReach(t *testing.T) {
	got := lanAddress()
	if got == "" {
		t.Skip("this machine has no private IPv4 address to share on")
	}

	ip := net.ParseIP(got)
	if ip == nil {
		t.Fatalf("%q is not an address at all", got)
	}
	if ip.To4() == nil {
		t.Fatalf("%q is not IPv4 — a phone being set up by hand takes four numbers", got)
	}
	if ip.IsLoopback() {
		t.Fatal("loopback means \"this machine\" on the phone too, so it would send the phone to itself")
	}
	if !ip.IsPrivate() {
		t.Fatalf("%q is not a local network address", got)
	}
}

package main

import (
	"runtime"
	"testing"

	"whitevpn-desktop/internal/capability"
	"whitevpn-desktop/internal/model"
)

// The interface offers or hides the tunnel based on this answer, so the
// statuses have to stay coherent whatever machine the test lands on: an
// offered tunnel never comes with a reason explaining why it cannot run, and
// every status the backend knows how to produce must survive the trip through
// JSON-shaped struct fields unchanged.
func TestRoutingCapabilitiesAreCoherent(t *testing.T) {
	app := &App{}
	caps := app.GetRoutingCapabilities()

	if caps.Platform != runtime.GOOS {
		t.Fatalf("platform %q does not match this machine (%s)", caps.Platform, runtime.GOOS)
	}
	switch caps.Tunnel.Status {
	case model.CapabilityAvailable, model.CapabilityExperimental:
		if caps.Tunnel.Reason != "" {
			t.Fatalf("an offered tunnel carries no refusal reason, got %q", caps.Tunnel.Reason)
		}
		if !capability.TunnelSelectable() {
			t.Fatal("available/experimental must be selectable")
		}
	case model.CapabilityRequiresApproval, model.CapabilityHelperMissing:
		if caps.Tunnel.Reason == "" {
			t.Fatalf("%s must say what would change it", caps.Tunnel.Status)
		}
		if capability.TunnelSelectable() {
			t.Fatalf("%s must not be selectable", caps.Tunnel.Status)
		}
	case model.CapabilityUnsupported:
	default:
		t.Fatalf("unknown tunnel status %q", caps.Tunnel.Status)
	}

	switch caps.SystemProxy.Status {
	case model.CapabilityAvailable:
		if len(caps.SystemProxy.Backends) == 0 {
			t.Fatal("an available system proxy names where the setting lives")
		}
	case model.CapabilityUnsupported:
		if caps.SystemProxy.Scope != "manual" || caps.SystemProxy.Reason == "" {
			t.Fatal("a bare window manager gets the manual scope and the reason why")
		}
	default:
		t.Fatalf("unknown system proxy status %q", caps.SystemProxy.Status)
	}
}

// The compatibility wrapper has to keep meaning what it always meant, because
// older frontends and scripts still ask it.
func TestTunnelSupportedMatchesCapability(t *testing.T) {
	want := capability.TunnelSelectable()
	if got := (&App{}).TunnelSupported(); got != want {
		t.Fatalf("TunnelSupported=%v, capability says %v", got, want)
	}
}

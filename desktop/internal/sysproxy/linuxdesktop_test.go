package sysproxy

import (
	"strings"
	"testing"
)

func gnomeArgLine(args [][]string, schema, key string) string {
	for _, call := range args {
		if len(call) == 4 && call[1] == schema && call[2] == key {
			return call[3]
		}
	}
	return ""
}

func TestGnomeApplyPointsEveryProtocolAtTheProxy(t *testing.T) {
	args := gnomeApplyArgs(State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass})

	if mode := gnomeArgLine(args, gnomeProxySchema, "mode"); mode != "manual" {
		t.Fatalf("expected manual mode, got %q", mode)
	}
	// https as well as http: a browser sends CONNECT to whatever the https entry
	// names, and an empty one means it goes direct — connected, and leaking.
	for _, child := range []string{"http", "https", "socks"} {
		schema := gnomeProxySchema + "." + child
		if host := gnomeArgLine(args, schema, "host"); host != "127.0.0.1" {
			t.Errorf("%s host = %q", child, host)
		}
		if port := gnomeArgLine(args, schema, "port"); port != "2080" {
			t.Errorf("%s port = %q", child, port)
		}
	}
}

func TestGnomeApplyOnlyTurnsTheModeOffWhenDisabling(t *testing.T) {
	args := gnomeApplyArgs(State{Enabled: false})
	if len(args) != 1 {
		t.Fatalf("disabling should be one call, got %d: %v", len(args), args)
	}
	if gnomeArgLine(args, gnomeProxySchema, "mode") != "none" {
		t.Fatalf("expected mode none, got %v", args)
	}
	// The host and port are deliberately left alone: clearing them would wipe a
	// proxy the user configured themselves before this app ever ran.
}

// `<local>` is WinINET's word for "any name without a dot". GNOME would take it
// literally and try to match a host called "<local>".
func TestGnomeIgnoreHostsDropsTheWindowsOnlyToken(t *testing.T) {
	value := gnomeIgnoreHosts(DefaultBypass)
	if strings.Contains(value, "<local>") {
		t.Fatalf("the Windows-only token survived: %s", value)
	}
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		t.Fatalf("expected a GVariant array literal, got %s", value)
	}
	if !strings.Contains(value, "'localhost'") {
		t.Fatalf("localhost should be bypassed: %s", value)
	}
}

func TestParseGnomeStateReadsWhatGsettingsPrints(t *testing.T) {
	// gsettings quotes strings and prefixes arrays with their type.
	state := parseGnomeState("'manual'", "'127.0.0.1'", "2080", "@as ['localhost', '127.0.0.0/8']")
	if !state.Enabled {
		t.Fatal("manual mode means enabled")
	}
	if state.Server != "127.0.0.1:2080" {
		t.Fatalf("server = %q", state.Server)
	}
	if state.Override != "localhost;127.0.0.0/8" {
		t.Fatalf("override = %q", state.Override)
	}

	off := parseGnomeState("'none'", "'127.0.0.1'", "2080", "@as []")
	if off.Enabled {
		t.Fatal("none mode means disabled")
	}
}

// What Apply writes, Current must read back as the same thing, or Verify
// reports a failure on settings that took.
func TestGnomeRoundTrips(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}
	args := gnomeApplyArgs(want)

	got := parseGnomeState(
		gnomeArgLine(args, gnomeProxySchema, "mode"),
		gnomeArgLine(args, gnomeProxySchema+".http", "host"),
		gnomeArgLine(args, gnomeProxySchema+".http", "port"),
		gnomeArgLine(args, gnomeProxySchema, "ignore-hosts"),
	)
	if !got.SameAs(State{Enabled: true, Server: want.Server, Override: got.Override}) {
		t.Fatalf("round trip lost the settings: %#v", got)
	}
	if got.Server != want.Server {
		t.Fatalf("server did not survive: %q", got.Server)
	}
}

func TestKDEApplyWritesManualProxyEntries(t *testing.T) {
	entries := kdeApplyEntries(State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass})

	if entries["ProxyType"] != "1" {
		t.Fatalf("ProxyType = %q, KDE's number for manual is 1", entries["ProxyType"])
	}
	for _, key := range []string{"httpProxy", "httpsProxy", "socksProxy"} {
		if !strings.Contains(entries[key], "127.0.0.1:2080") {
			t.Errorf("%s = %q", key, entries[key])
		}
	}
	if strings.Contains(entries["NoProxyFor"], "<local>") {
		t.Fatalf("the Windows-only token survived: %q", entries["NoProxyFor"])
	}
	if !strings.Contains(entries["NoProxyFor"], "localhost") {
		t.Fatalf("localhost should be bypassed: %q", entries["NoProxyFor"])
	}
}

func TestKDEApplyDisables(t *testing.T) {
	entries := kdeApplyEntries(State{Enabled: false})
	if entries["ProxyType"] != "0" {
		t.Fatalf("ProxyType = %q, KDE's number for none is 0", entries["ProxyType"])
	}
}

func TestParseKDEStateHandlesBothProxyFormats(t *testing.T) {
	// The form this app writes.
	modern := parseKDEState("1", "http://127.0.0.1:2080", "localhost,127.0.0.1")
	if !modern.Enabled || modern.Server != "127.0.0.1:2080" {
		t.Fatalf("modern form: %#v", modern)
	}
	// The older KDE form, which separates host and port with a space and which
	// a machine configured before this app ran may still hold.
	legacy := parseKDEState("1", "http://127.0.0.1 8080", "")
	if legacy.Server != "127.0.0.1:8080" {
		t.Fatalf("legacy form: %q", legacy.Server)
	}
	off := parseKDEState("0", "", "")
	if off.Enabled {
		t.Fatal("ProxyType 0 means disabled")
	}
}

func TestKDERoundTrips(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}
	entries := kdeApplyEntries(want)
	got := parseKDEState(entries["ProxyType"], entries["httpProxy"], entries["NoProxyFor"])
	if !got.Enabled || got.Server != want.Server {
		t.Fatalf("round trip lost the settings: %#v", got)
	}
}

func TestSplitProxyEndpointRefusesWhatIsNotHostPort(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1", "127.0.0.1:", "127.0.0.1:abc", "nonsense"} {
		if host, port := splitProxyEndpoint(value); host != "" || port != 0 {
			t.Errorf("%q parsed as %q/%d", value, host, port)
		}
	}
	if host, port := splitProxyEndpoint(" 127.0.0.1:2080 "); host != "127.0.0.1" || port != 2080 {
		t.Errorf("got %q/%d", host, port)
	}
}

package model

import "testing"

// The defaults are the phone's, so that someone moving across finds the app
// behaving the way they already expect.
func TestDefaultsMatchThePhone(t *testing.T) {
	settings := DefaultWhiteVPNSettings()

	if settings.CountryCode != "" {
		t.Errorf("location should start automatic, got %q", settings.CountryCode)
	}
	if settings.SplitTunnel.Mode != SplitTunnelOff {
		t.Errorf("split tunnel should start off, got %q", settings.SplitTunnel.Mode)
	}
	if settings.TLSIntegrityEnabled {
		t.Error("TLS integrity starts off on the phone")
	}
	if settings.AmneziaNoise.Enabled {
		t.Error("noise starts off on the phone")
	}
	if settings.AmneziaNoise.Count != 5 || settings.AmneziaNoise.MinSize != 50 || settings.AmneziaNoise.MaxSize != 100 {
		t.Errorf("noise defaults should be 5/50/100, got %+v", settings.AmneziaNoise)
	}
	if settings.DNSPrivacy.Mode != DNSPrivacyAutomatic {
		t.Errorf("DNS privacy starts automatic, got %q", settings.DNSPrivacy.Mode)
	}
	if settings.DNSPrivacy.DoHURL != "https://1.1.1.1/dns-query" {
		t.Errorf("unexpected DoH default: %q", settings.DNSPrivacy.DoHURL)
	}
	if settings.DNSPrivacy.DoTEndpoint != "tls://1.1.1.1:853" {
		t.Errorf("unexpected DoT default: %q", settings.DNSPrivacy.DoTEndpoint)
	}
}

// A value out of range is replaced rather than clamped: a clamped one looks like
// the app ignoring what was typed.
func TestNoiseOutOfRangeFallsBackToTheDefault(t *testing.T) {
	for _, noise := range []AmneziaNoiseSettings{
		{Count: 0, MinSize: 50, MaxSize: 100},
		{Count: 21, MinSize: 50, MaxSize: 100},
		{Count: 5, MinSize: 0, MaxSize: 100},
		{Count: 5, MinSize: 50, MaxSize: 5000},
	} {
		settings := DefaultWhiteVPNSettings()
		settings.AmneziaNoise = noise
		got := NormalizeWhiteVPNSettings(settings).AmneziaNoise
		if got.Count < MinNoiseCount || got.Count > MaxNoiseCount ||
			got.MinSize < MinNoiseSize || got.MaxSize > MaxNoiseSize {
			t.Fatalf("%+v was not repaired: %+v", noise, got)
		}
	}
}

func TestNoiseMinAboveMaxIsReset(t *testing.T) {
	settings := DefaultWhiteVPNSettings()
	settings.AmneziaNoise = AmneziaNoiseSettings{Count: 5, MinSize: 900, MaxSize: 100}
	got := NormalizeWhiteVPNSettings(settings).AmneziaNoise
	if got.MinSize > got.MaxSize {
		t.Fatalf("an inverted range survived: %+v", got)
	}
}

// VPN-only with nothing selected would route no traffic at all, which is
// indistinguishable from a broken tunnel.
func TestVPNOnlyWithNothingSelectedFallsBackToOff(t *testing.T) {
	settings := DefaultWhiteVPNSettings()
	settings.SplitTunnel = SplitTunnelSettings{Mode: SplitTunnelVPNOnly, Processes: []string{}}
	if got := NormalizeWhiteVPNSettings(settings).SplitTunnel.Mode; got != SplitTunnelOff {
		t.Fatalf("expected off, got %q", got)
	}
}

func TestVPNOnlyWithSelectionSurvives(t *testing.T) {
	settings := DefaultWhiteVPNSettings()
	settings.SplitTunnel = SplitTunnelSettings{Mode: SplitTunnelVPNOnly, Processes: []string{"firefox.exe"}}
	if got := NormalizeWhiteVPNSettings(settings).SplitTunnel.Mode; got != SplitTunnelVPNOnly {
		t.Fatalf("expected vpn-only to survive, got %q", got)
	}
}

// The phone allows five, and the connect flow walks them in order, so a longer
// list would change how long connecting takes.
func TestFrontingIPsAreCappedAndDeduplicated(t *testing.T) {
	settings := DefaultWhiteVPNSettings()
	settings.FrontingIPs = []string{"1.1.1.1", "1.1.1.1", " 2.2.2.2 ", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", ""}

	got := NormalizeWhiteVPNSettings(settings).FrontingIPs
	if len(got) != MaxFrontingIPs {
		t.Fatalf("expected %d entries, got %v", MaxFrontingIPs, got)
	}
	if got[1] != "2.2.2.2" {
		t.Fatalf("entries should be trimmed: %v", got)
	}
}

func TestUnknownModesFallBackRatherThanPersist(t *testing.T) {
	settings := DefaultWhiteVPNSettings()
	settings.SplitTunnel.Mode = "whatever"
	settings.DNSPrivacy.Mode = "quic"

	got := NormalizeWhiteVPNSettings(settings)
	if got.SplitTunnel.Mode != SplitTunnelOff {
		t.Errorf("split tunnel mode %q survived", got.SplitTunnel.Mode)
	}
	if got.DNSPrivacy.Mode != DNSPrivacyAutomatic {
		t.Errorf("DNS mode %q survived", got.DNSPrivacy.Mode)
	}
}

// An empty resolver would leave the engine with nothing to ask.
func TestBlankResolversFallBackToTheDefaults(t *testing.T) {
	settings := DefaultWhiteVPNSettings()
	settings.DNSPrivacy.DoHURL = "   "
	settings.DNSPrivacy.DoTEndpoint = ""

	got := NormalizeWhiteVPNSettings(settings).DNSPrivacy
	if got.DoHURL != DefaultDoHURL || got.DoTEndpoint != DefaultDoTEndpoint {
		t.Fatalf("blank resolvers were not repaired: %+v", got)
	}
}

// A state read from an older file has a zero settings block; it must come back
// usable rather than with a split tunnel mode of "" and no resolvers.
func TestAZeroValueBlockNormalisesToTheDefaults(t *testing.T) {
	got := NormalizeWhiteVPNSettings(WhiteVPNSettings{})
	if got.SplitTunnel.Mode != SplitTunnelOff || got.DNSPrivacy.Mode != DNSPrivacyAutomatic {
		t.Fatalf("zero value did not normalise: %+v", got)
	}
	if got.AmneziaNoise.Count != DefaultNoiseCount {
		t.Fatalf("noise did not normalise: %+v", got.AmneziaNoise)
	}
	if got.DNSPrivacy.DoHURL == "" || got.DNSPrivacy.DoTEndpoint == "" {
		t.Fatalf("resolvers left empty: %+v", got.DNSPrivacy)
	}
}

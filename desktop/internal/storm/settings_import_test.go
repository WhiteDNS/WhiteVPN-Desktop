package storm

import (
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestParseSettingsProfileTOMLIgnoresConnectionFields(t *testing.T) {
	raw := `
DOMAINS = ["v.example.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
LISTEN_IP = "127.0.0.2"
LISTEN_PORT = 19087
SOCKS5_AUTH = true
SOCKS5_USER = "user#name"
SOCKS5_PASS = "pass"
LOCAL_DNS_ENABLED = true
LOCAL_DNS_PORT = 5353
UPLOAD_PACKET_DUPLICATION_COUNT = 4
DOWNLOAD_PACKET_DUPLICATION_COUNT = 8
STARTUP_MODE = "logs"
LOG_LEVEL = "DEBUG"
`

	profile, err := ParseSettingsProfileTOML(raw, "Imported.toml", model.ImportTypeStormDNS)
	if err != nil {
		t.Fatal(err)
	}

	if profile.ID != "" || profile.Name != "Imported" {
		t.Fatalf("unexpected imported identity: %#v", profile)
	}
	if profile.ImportType != model.ImportTypeStormDNS {
		t.Fatalf("unexpected import type: %q", profile.ImportType)
	}
	if profile.StormDNSListenIP != "127.0.0.2" || profile.StormDNSListenPort != 19087 {
		t.Fatalf("unexpected StormDNS listener: %#v", profile)
	}
	if !profile.SOCKS5Authentication || profile.SOCKSUsername != "user#name" || profile.SOCKSPassword != "pass" {
		t.Fatalf("unexpected SOCKS settings: %#v", profile)
	}
	if !profile.LocalDNSEnabled || profile.LocalDNSPort != 5353 {
		t.Fatalf("unexpected local DNS settings: %#v", profile)
	}
	if profile.UploadDuplication != 4 || profile.DownloadDuplication != 8 {
		t.Fatalf("unexpected duplication settings: %#v", profile)
	}
	if profile.StartupMode != "logs" || profile.LogLevel != "DEBUG" {
		t.Fatalf("unexpected general settings: %#v", profile)
	}
}

func TestParseSettingsProfileTOMLRoundTripsExport(t *testing.T) {
	settings := model.DefaultSettingsProfile()
	settings.Name = "Original"
	settings.StormDNSListenPort = 19087
	settings.MTUTestTimeoutResolvers = 3.5
	settings.SessionInitRacingCount = 4
	settings.MTUStartupLossVerifyEnabled = false
	settings.MTUStartupLossVerifySamples = 5
	settings.MTUStartupLossVerifyMaxLossPct = 20
	settings.MTUStartupLossVerifyCandidates = 4
	settings.MTURecheckEnabled = false
	settings.MTURecheckIntervalMinutes = 15

	exported := RenderExportClientTOML(settings)
	if strings.Contains(exported, "ENCRYPTION_KEY") {
		t.Fatalf("test export unexpectedly included connection fields:\n%s", exported)
	}

	profile, err := ParseSettingsProfileTOML(exported, "Round trip", model.ImportTypeStormDNS)
	if err != nil {
		t.Fatal(err)
	}

	if profile.Name != "Round trip" || profile.StormDNSListenPort != 19087 {
		t.Fatalf("unexpected round-trip profile: %#v", profile)
	}
	if profile.ImportType != model.ImportTypeMasterDNS {
		t.Fatalf("expected marker to select MasterDNS, got %q", profile.ImportType)
	}
	if profile.MTUTestTimeoutResolvers != 3.5 || profile.SessionInitRacingCount != 4 {
		t.Fatalf("unexpected round-trip runtime knobs: %#v", profile)
	}
	if profile.MTUStartupLossVerifyEnabled ||
		profile.MTUStartupLossVerifySamples != 5 ||
		profile.MTUStartupLossVerifyMaxLossPct != 20 ||
		profile.MTUStartupLossVerifyCandidates != 4 ||
		profile.MTURecheckEnabled ||
		profile.MTURecheckIntervalMinutes != 15 {
		t.Fatalf("unexpected round-trip MTU adaptation settings: %#v", profile)
	}
}

func TestParseSettingsProfileTOMLRejectsNonSettingsTOML(t *testing.T) {
	_, err := ParseSettingsProfileTOML(`DOMAINS = ["v.example.com"]`, "", model.ImportTypeMasterDNS)
	if err == nil {
		t.Fatal("expected missing settings error")
	}
}

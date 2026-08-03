package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestStoreLoadDefaultsWhenMissing(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "state.json"))
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.SelectedConnectionProfileID != model.DefaultConnectionProfileID {
		t.Fatalf("unexpected selected connection: %s", state.SelectedConnectionProfileID)
	}
	if len(state.ConnectionProfiles) != 1 || len(state.SettingsProfiles) != 1 {
		t.Fatalf("expected default profiles, got %#v", state)
	}
	settings := state.SettingsProfiles[0]
	if settings.LocalDNSEnabled || settings.LocalDNSPort != 53 {
		t.Fatalf("expected Android default local DNS settings, got %#v", settings)
	}
}

func TestDefaultResolverProfileUsesKnownPublicResolvers(t *testing.T) {
	want := []string{
		"1.1.1.1",
		"1.0.0.1",
		"8.8.8.8",
		"8.8.4.4",
		"9.9.9.9",
		"149.112.112.112",
		"208.67.222.222",
		"208.67.220.220",
		"94.140.14.14",
		"94.140.15.15",
	}
	got := strings.Split(model.DefaultResolverProfile().ResolverText, "\n")
	if len(got) != len(want) {
		t.Fatalf("expected %d default resolvers, got %d: %#v", len(want), len(got), got)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("unexpected default resolver at %d: got %q want %q", idx, got[idx], want[idx])
		}
	}
}

func TestNormalizeStateBackfillsEmptyDefaultResolverProfile(t *testing.T) {
	state := model.DefaultAppState()
	state.ResolverProfiles[0].ResolverText = ""

	normalized := NormalizeState(state)
	if got, want := normalized.ResolverProfiles[0].ResolverText, model.DefaultResolverProfile().ResolverText; got != want {
		t.Fatalf("expected empty default resolver profile to be backfilled, got %q want %q", got, want)
	}
}

func TestNormalizeStateKeepsCustomDefaultResolverProfileText(t *testing.T) {
	state := model.DefaultAppState()
	state.ResolverProfiles[0].ResolverText = "4.4.4.4"

	normalized := NormalizeState(state)
	if got := normalized.ResolverProfiles[0].ResolverText; got != "4.4.4.4" {
		t.Fatalf("expected custom default resolver text to persist, got %q", got)
	}
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)
	state := model.DefaultAppState()
	state.SettingsProfiles[0].SingBoxEnabled = false
	state.ConnectionProfiles = append(state.ConnectionProfiles, model.ConnectionProfile{
		ID:               "custom",
		Name:             "Custom",
		Domain:           "v.example.com.",
		EncryptionKey:    "key",
		EncryptionMethod: 2,
	})
	state.SelectedConnectionProfileID = "custom"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SelectedConnectionProfileID != "custom" {
		t.Fatalf("selected profile not persisted: %#v", loaded)
	}
	if loaded.ConnectionProfiles[1].Domain != "v.example.com" {
		t.Fatalf("domain was not normalized: %#v", loaded.ConnectionProfiles[1])
	}
	if loaded.Runtime.Status != model.RuntimeDisconnected {
		t.Fatalf("runtime state should not persist as active: %#v", loaded.Runtime)
	}
	if !loaded.SettingsProfiles[0].SingBoxEnabled {
		t.Fatalf("proxy core should be forced on: %#v", loaded.SettingsProfiles[0])
	}
}

func TestStoreRecoversFromCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.SelectedSettingsProfileID != model.DefaultSettingsProfileID {
		t.Fatalf("expected default state recovery, got %#v", state)
	}
}

func TestNormalizeStateMigratesLegacyDefaultLocalDNS(t *testing.T) {
	state := model.DefaultAppState()
	state.SettingsProfiles[0].LocalDNSEnabled = true
	state.SettingsProfiles[0].LocalDNSPort = 10888

	normalized := NormalizeState(state)
	settings := normalized.SettingsProfiles[0]
	if settings.LocalDNSEnabled || settings.LocalDNSPort != 53 {
		t.Fatalf("expected legacy default local DNS settings to migrate, got %#v", settings)
	}
}

func TestNormalizeStateReplacesEditedDefaultSettingsProfile(t *testing.T) {
	state := model.DefaultAppState()
	state.SettingsProfiles[0].Name = "Edited default"
	state.SettingsProfiles[0].ListenPort = 32000
	state.SettingsProfiles[0].LocalDNSEnabled = true
	state.SettingsProfiles[0].LocalDNSPort = 10888
	state.SettingsProfiles[0].LogLevel = "DEBUG"

	normalized := NormalizeState(state)
	settings := normalized.SettingsProfiles[0]
	defaults := model.DefaultSettingsProfile()
	if settings != defaults {
		t.Fatalf("expected edited default settings profile to be replaced, got %#v want %#v", settings, defaults)
	}
}

func TestNormalizeStateResetsOutOfRangeMasterDNSDuplication(t *testing.T) {
	state := model.DefaultAppState()
	state.SettingsProfiles[0].UploadDuplication = 90
	state.SettingsProfiles[0].DownloadDuplication = 90

	normalized := NormalizeState(state)
	settings := normalized.SettingsProfiles[0]
	if settings.UploadDuplication != 1 || settings.DownloadDuplication != 3 {
		t.Fatalf("expected MasterDNS duplication defaults, got upload=%d download=%d", settings.UploadDuplication, settings.DownloadDuplication)
	}
}

func TestNormalizeStateAllowsZeroMasterDNSDuplication(t *testing.T) {
	state := model.DefaultAppState()
	custom := model.DefaultSettingsProfile()
	custom.ID = "settings-zero-duplication"
	custom.Name = "Zero duplication"
	custom.UploadDuplication = 0
	custom.DownloadDuplication = 0
	state.SettingsProfiles = append(state.SettingsProfiles, custom)
	state.SelectedSettingsProfileID = custom.ID

	normalized := NormalizeState(state)
	var settings model.SettingsProfile
	for _, profile := range normalized.SettingsProfiles {
		if profile.ID == custom.ID {
			settings = profile
			break
		}
	}
	if settings.ID == "" {
		t.Fatalf("expected custom settings profile to persist: %#v", normalized.SettingsProfiles)
	}
	if settings.UploadDuplication != 0 || settings.DownloadDuplication != 0 {
		t.Fatalf("expected zero MasterDNS duplication to persist in custom profile, got upload=%d download=%d", settings.UploadDuplication, settings.DownloadDuplication)
	}
}

func TestNormalizeSettingsConnectionStartupModeDefaultsStandardAndKeepsFullScan(t *testing.T) {
	settings := NormalizeSettingsProfile(model.SettingsProfile{Name: "Custom"})
	if settings.ConnectionStartupMode != model.ConnectionStartupModeStandard {
		t.Fatalf("expected missing startup mode to default to standard, got %q", settings.ConnectionStartupMode)
	}

	settings = NormalizeSettingsProfile(model.SettingsProfile{
		Name:                  "Custom",
		ConnectionStartupMode: "fast",
	})
	if settings.ConnectionStartupMode != model.ConnectionStartupModeStandard {
		t.Fatalf("expected legacy fast startup mode to normalize to standard, got %q", settings.ConnectionStartupMode)
	}

	settings = NormalizeSettingsProfile(model.SettingsProfile{
		Name:                  "Custom",
		ConnectionStartupMode: model.ConnectionStartupModeFullScan,
	})
	if settings.ConnectionStartupMode != model.ConnectionStartupModeFullScan {
		t.Fatalf("expected full scan mode to persist, got %q", settings.ConnectionStartupMode)
	}
}

func TestNormalizeSettingsDefaultsMTURecheckAndStartupLoss(t *testing.T) {
	settings := NormalizeSettingsProfile(model.SettingsProfile{Name: "Custom"})
	if settings.MTUStartupLossVerifyEnabled ||
		settings.MTUStartupLossVerifySamples != 3 ||
		settings.MTUStartupLossVerifyMaxLossPct != 34 ||
		settings.MTUStartupLossVerifyCandidates != 3 {
		t.Fatalf("expected startup loss defaults, got %#v", settings)
	}
	if settings.MTURecheckEnabled || settings.MTURecheckIntervalMinutes != 5 {
		t.Fatalf("expected mtu recheck defaults, got %#v", settings)
	}

	settings = NormalizeSettingsProfile(model.SettingsProfile{
		Name:                           "Custom",
		MTUStartupLossVerifyEnabled:    false,
		MTUStartupLossVerifySamples:    5,
		MTUStartupLossVerifyMaxLossPct: 20,
		MTUStartupLossVerifyCandidates: 4,
		MTURecheckEnabled:              false,
		MTURecheckIntervalMinutes:      15,
	})
	if settings.MTUStartupLossVerifyEnabled || settings.MTURecheckEnabled {
		t.Fatalf("expected explicit disabled MTU settings to persist, got %#v", settings)
	}
	if settings.MTUStartupLossVerifySamples != 5 || settings.MTUStartupLossVerifyMaxLossPct != 20 || settings.MTUStartupLossVerifyCandidates != 4 || settings.MTURecheckIntervalMinutes != 15 {
		t.Fatalf("unexpected explicit MTU settings after normalization: %#v", settings)
	}
}

func TestNormalizeV2RaySettingsAllowLANControlsListenIP(t *testing.T) {
	settings := NormalizeV2RaySettingsProfile(model.V2RaySettingsProfile{
		Name:     "LAN",
		AllowLAN: true,
	})
	if !settings.AllowLAN || settings.ListenIP != "0.0.0.0" {
		t.Fatalf("expected LAN-enabled V2Ray settings to listen on all interfaces, got %#v", settings)
	}

	settings = NormalizeV2RaySettingsProfile(model.V2RaySettingsProfile{
		Name:     "Legacy LAN",
		ListenIP: "0.0.0.0",
	})
	if !settings.AllowLAN || settings.ListenIP != "0.0.0.0" {
		t.Fatalf("expected legacy wildcard listen IP to backfill allow LAN, got %#v", settings)
	}

	settings = NormalizeV2RaySettingsProfile(model.V2RaySettingsProfile{Name: "Local"})
	if settings.AllowLAN || settings.ListenIP != "127.0.0.1" {
		t.Fatalf("expected V2Ray settings to default to localhost only, got %#v", settings)
	}
}

func TestNormalizeV2RayProfileDefaultsWebSocketEarlyDataHeader(t *testing.T) {
	profile := NormalizeV2RayProfile(model.V2RayProfile{
		Name:               "WS",
		Network:            "ws",
		WebSocketEarlyData: 2048,
	})

	if profile.WebSocketEarlyData != 2048 || profile.WebSocketEarlyDataHeader != "Sec-WebSocket-Protocol" {
		t.Fatalf("expected WebSocket early-data defaults, got %#v", profile)
	}
}

func TestNormalizeV2RayProfileKeepsSupportedTransportAliases(t *testing.T) {
	tests := map[string]string{
		"raw":         "tcp",
		"mkcp":        "kcp",
		"kcp":         "kcp",
		"h2":          "http",
		"quic":        "quic",
		"httpUpgrade": "httpupgrade",
		"split-http":  "xhttp",
		"split_http":  "xhttp",
		"websocket":   "ws",
		"unsupported": "tcp",
	}

	for input, want := range tests {
		got := NormalizeV2RayProfile(model.V2RayProfile{Name: "Transport", Network: input}).Network
		if got != want {
			t.Fatalf("network %q normalized to %q, want %q", input, got, want)
		}
	}
}

func TestDefaultV2RaySettingsEnableSystemProxy(t *testing.T) {
	settings := model.DefaultV2RaySettingsProfile()
	if !settings.SetSystemProxy {
		t.Fatal("expected default V2Ray settings to enable system proxy")
	}

	normalized := NormalizeState(model.AppState{})
	if len(normalized.V2RaySettingsProfiles) == 0 || !normalized.V2RaySettingsProfiles[0].SetSystemProxy {
		t.Fatalf("expected normalized default V2Ray settings to enable system proxy, got %#v", normalized.V2RaySettingsProfiles)
	}
}

func TestNormalizeV2RaySettingsTunDefaultsAndLegacyMigration(t *testing.T) {
	defaults := model.DefaultV2RaySettingsProfile()
	if defaults.TunEnabled || defaults.TunMTU != 1492 || !defaults.TunIPv6 || strings.TrimSpace(defaults.TunInterfaceName) == "" {
		t.Fatalf("unexpected default TUN settings: %#v", defaults)
	}

	legacy := NormalizeV2RaySettingsProfile(model.V2RaySettingsProfile{Name: "Legacy"})
	if legacy.TunEnabled || legacy.TunMTU != defaults.TunMTU || !legacy.TunIPv6 || legacy.TunInterfaceName != defaults.TunInterfaceName {
		t.Fatalf("expected legacy V2Ray settings to get TUN defaults, got %#v want %#v", legacy, defaults)
	}

	custom := NormalizeV2RaySettingsProfile(model.V2RaySettingsProfile{
		Name:             "Custom",
		TunEnabled:       true,
		TunMTU:           1280,
		TunIPv6:          false,
		TunInterfaceName: " tun-test0 ",
	})
	if !custom.TunEnabled || custom.TunMTU != 1280 || custom.TunIPv6 || custom.TunInterfaceName != "tun-test0" {
		t.Fatalf("expected explicit TUN settings to persist, got %#v", custom)
	}
}

func TestNormalizeStateKeepsLegacyStormDNSMaxDuplication(t *testing.T) {
	state := model.DefaultAppState()
	stormSettings := model.DefaultSettingsProfile()
	stormSettings.ID = "settings-storm"
	stormSettings.Name = "StormDNS"
	stormSettings.ImportType = model.ImportTypeStormDNS
	stormSettings.UploadDuplication = 90
	stormSettings.DownloadDuplication = 90
	state.SettingsProfiles = append(state.SettingsProfiles, stormSettings)

	normalized := NormalizeState(state)
	var settings model.SettingsProfile
	for _, profile := range normalized.SettingsProfiles {
		if profile.ID == stormSettings.ID {
			settings = profile
			break
		}
	}
	if settings.UploadDuplication != 90 || settings.DownloadDuplication != 90 {
		t.Fatalf("expected StormDNS max duplication to persist, got upload=%d download=%d", settings.UploadDuplication, settings.DownloadDuplication)
	}
}

func TestNormalizeStateDoesNotCreateDefaultV2RayProfile(t *testing.T) {
	state := model.DefaultAppState()
	state.V2RayProfiles = nil
	state.SelectedV2RayProfileID = model.DefaultV2RayProfileID

	normalized := NormalizeState(state)
	if len(normalized.V2RayProfiles) != 0 {
		t.Fatalf("expected no default V2Ray profile, got %#v", normalized.V2RayProfiles)
	}
	if normalized.SelectedV2RayProfileID != "" {
		t.Fatalf("expected empty selected V2Ray profile, got %q", normalized.SelectedV2RayProfileID)
	}
}

func TestNormalizeStateRemovesEmptyLegacyDefaultV2RayProfile(t *testing.T) {
	state := model.DefaultAppState()
	state.V2RayProfiles = []model.V2RayProfile{model.DefaultV2RayProfile()}

	normalized := NormalizeState(state)
	if len(normalized.V2RayProfiles) != 0 {
		t.Fatalf("expected empty default V2Ray profile to be removed, got %#v", normalized.V2RayProfiles)
	}
}

func TestNormalizeStateKeepsConfiguredLegacyDefaultV2RayProfile(t *testing.T) {
	state := model.DefaultAppState()
	defaultProfile := model.DefaultV2RayProfile()
	defaultProfile.Server = "vless.example.com"
	defaultProfile.UUID = "11111111-1111-1111-1111-111111111111"
	state.V2RayProfiles = []model.V2RayProfile{defaultProfile}
	state.SelectedV2RayProfileID = model.DefaultV2RayProfileID

	normalized := NormalizeState(state)
	if len(normalized.V2RayProfiles) != 1 {
		t.Fatalf("expected configured default V2Ray profile to be kept, got %#v", normalized.V2RayProfiles)
	}
	if normalized.SelectedV2RayProfileID != model.DefaultV2RayProfileID {
		t.Fatalf("expected configured default V2Ray profile to remain selected, got %q", normalized.SelectedV2RayProfileID)
	}
}

func TestStoreBackupRoundTripIncludesFileBackedResolvers(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "resolvers.txt")
	if err := os.WriteFile(sourcePath, []byte("1.1.1.1\n8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sourceStore := NewStore(filepath.Join(tempDir, "source", "state.json"))
	resolverProfile, err := sourceStore.ImportResolverFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}

	state := model.DefaultAppState()
	state.ConnectionProfiles = append(state.ConnectionProfiles, model.ConnectionProfile{
		ID:                "custom",
		Name:              "Custom",
		Domain:            "v.example.com",
		EncryptionKey:     "key",
		EncryptionMethod:  1,
		ResolverProfileID: resolverProfile.ID,
	})
	state.SelectedConnectionProfileID = "custom"
	state.ResolverProfiles = append(state.ResolverProfiles, resolverProfile)
	state.SelectedResolverProfileID = resolverProfile.ID
	state.Runtime.Status = model.RuntimeConnected

	backup, err := sourceStore.ExportBackup(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(backup, resolverProfile.ResolverFile) {
		t.Fatalf("backup should not expose local resolver file path:\n%s", backup)
	}
	if !strings.Contains(backup, "1.1.1.1") {
		t.Fatalf("backup should include resolver file contents:\n%s", backup)
	}

	targetStore := NewStore(filepath.Join(tempDir, "target", "state.json"))
	restored, err := targetStore.ImportBackup(backup)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Runtime.Status != model.RuntimeDisconnected {
		t.Fatalf("backup restore should reset runtime state, got %#v", restored.Runtime)
	}
	if restored.SelectedConnectionProfileID != "custom" {
		t.Fatalf("selected connection was not restored: %#v", restored)
	}

	var restoredResolver model.ResolverProfile
	for _, profile := range restored.ResolverProfiles {
		if profile.ID == resolverProfile.ID {
			restoredResolver = profile
			break
		}
	}
	if !resolverProfileIsFileBacked(restoredResolver) {
		t.Fatalf("expected file-backed resolver after restore, got %#v", restoredResolver)
	}
	if restoredResolver.ResolverFile == resolverProfile.ResolverFile {
		t.Fatalf("restore should create a managed resolver file in the target store")
	}
	raw, err := os.ReadFile(restoredResolver.ResolverFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "8.8.8.8") {
		t.Fatalf("restored resolver file missing content: %s", raw)
	}
}

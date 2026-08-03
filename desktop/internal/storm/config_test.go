package storm

import (
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestBuildLaunchConfigRendersMasterDNSClientFiles(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0] = model.ConnectionProfile{
		ID:                model.DefaultConnectionProfileID,
		Name:              "Connection",
		Domain:            "v.example.com",
		EncryptionKey:     `abc"123`,
		EncryptionMethod:  1,
		ResolverProfileID: model.DefaultResolverProfileID,
	}
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8:5353"

	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}

	required := []string{
		`# WHITEDNS_IMPORT_TYPE = "masterdns"`,
		`DOMAINS = ["v.example.com"]`,
		`DATA_ENCRYPTION_METHOD = 1`,
		`ENCRYPTION_KEY = "abc\"123"`,
		`PROTOCOL_TYPE = "SOCKS5"`,
		`LISTEN_PORT = 10887`,
		`PACKET_DUPLICATION_COUNT = 1`,
		`SETUP_PACKET_DUPLICATION_COUNT = 3`,
		`UPLOAD_COMPRESSION_TYPE = 2`,
		`DOWNLOAD_COMPRESSION_TYPE = 2`,
		`MIN_UPLOAD_MTU = 40`,
		`MIN_DOWNLOAD_MTU = 300`,
		`MAX_UPLOAD_MTU = 140`,
		`MAX_DOWNLOAD_MTU = 3000`,
		`MTU_TEST_RETRIES = 3`,
		`MTU_TEST_TIMEOUT = 2.5`,
		`MTU_TEST_PARALLELISM = 100`,
		`MTU_STARTUP_LOSS_VERIFY_ENABLED = false`,
		`MTU_STARTUP_LOSS_VERIFY_SAMPLES = 3`,
		`MTU_STARTUP_LOSS_VERIFY_MAX_LOSS_PERCENT = 34`,
		`MTU_STARTUP_LOSS_VERIFY_CANDIDATES = 3`,
		`MTU_RECHECK_ENABLED = false`,
		`MTU_RECHECK_INTERVAL_MINUTES = 5`,
		`TUNNEL_PROCESS_WORKERS = 4`,
		`RX_CHANNEL_SIZE = 2048`,
	}
	for _, line := range required {
		if !strings.Contains(cfg.ClientTOML, line) {
			t.Fatalf("rendered TOML missing %q:\n%s", line, cfg.ClientTOML)
		}
	}
	if cfg.Resolvers != "1.1.1.1\n8.8.8.8:5353" {
		t.Fatalf("unexpected resolvers: %q", cfg.Resolvers)
	}
}

func TestBuildLaunchConfigRendersXrayFrontend(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].EncryptionKey = "key"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"

	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CoreEnabled {
		t.Fatal("expected Xray core to be enabled")
	}
	if !strings.Contains(cfg.ClientTOML, `LISTEN_PORT = 10887`) {
		t.Fatalf("expected MasterDNS/StormDNS to use internal port:\n%s", cfg.ClientTOML)
	}
	if !strings.Contains(cfg.CoreConfig, `"port": 10886`) {
		t.Fatalf("expected Xray to use public port:\n%s", cfg.CoreConfig)
	}
}

func TestBuildLaunchConfigWithSettingsRendersProvidedSettings(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].EncryptionKey = "key"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"

	settings := model.DefaultSettingsProfile()
	settings.ID = "settings-export"
	settings.Name = "Export"
	settings.StormDNSListenPort = 19087
	settings.LocalDNSPort = 19088
	settings.UploadDuplication = 5
	settings.LogLevel = "DEBUG"

	cfg, err := BuildLaunchConfigWithSettings(state, settings)
	if err != nil {
		t.Fatal(err)
	}

	required := []string{
		`LISTEN_PORT = 19087`,
		`LOCAL_DNS_PORT = 19088`,
		`PACKET_DUPLICATION_COUNT = 5`,
		`LOG_LEVEL = "DEBUG"`,
	}
	for _, line := range required {
		if !strings.Contains(cfg.ClientTOML, line) {
			t.Fatalf("rendered TOML missing %q:\n%s", line, cfg.ClientTOML)
		}
	}
}

func TestBuildLaunchConfigRendersZeroMasterDNSDuplicationAsSingleSend(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].EncryptionKey = "key"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"

	settings := model.DefaultSettingsProfile()
	settings.UploadDuplication = 0
	settings.DownloadDuplication = 0

	cfg, err := BuildLaunchConfigWithSettings(state, settings)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.UploadDuplication != 0 || cfg.Settings.DownloadDuplication != 0 {
		t.Fatalf("expected desktop settings to preserve zero duplication: %#v", cfg.Settings)
	}
	for _, line := range []string{
		`PACKET_DUPLICATION_COUNT = 1`,
		`SETUP_PACKET_DUPLICATION_COUNT = 1`,
	} {
		if !strings.Contains(cfg.ClientTOML, line) {
			t.Fatalf("rendered TOML missing %q:\n%s", line, cfg.ClientTOML)
		}
	}
}

func TestRenderExportClientTOMLOmitsConnectionFields(t *testing.T) {
	settings := model.DefaultSettingsProfile()
	settings.StormDNSListenPort = 19087
	settings.LocalDNSPort = 19088
	settings.UploadDuplication = 5

	toml := RenderExportClientTOML(settings)

	for _, line := range []string{
		`DOMAINS =`,
		`DATA_ENCRYPTION_METHOD =`,
		`ENCRYPTION_KEY =`,
	} {
		if strings.Contains(toml, line) {
			t.Fatalf("export TOML should omit %q:\n%s", line, toml)
		}
	}

	for _, line := range []string{
		`LISTEN_PORT = 19087`,
		`LOCAL_DNS_PORT = 19088`,
		`PACKET_DUPLICATION_COUNT = 5`,
	} {
		if !strings.Contains(toml, line) {
			t.Fatalf("export TOML missing %q:\n%s", line, toml)
		}
	}
}

func TestRenderRuntimeClientTOMLForcesAppOwnedMTUResolverStateFile(t *testing.T) {
	connection := model.DefaultConnectionProfile()
	connection.Domain = "v.example.com"
	connection.EncryptionKey = "key"
	settings := model.DefaultSettingsProfile()
	settings.SaveMTUServersToFile = false
	settings.MTUServersFileName = "user-file.log"

	toml := RenderRuntimeClientTOML(connection, settings, "/tmp/.wd-123.mtu-resolvers.log")

	for _, line := range []string{
		`SAVE_MTU_SERVERS_TO_FILE = true`,
		`MTU_SERVERS_FILE_NAME = "/tmp/.wd-123.mtu-resolvers.log"`,
		`MTU_SERVERS_FILE_FORMAT = "WHITEDNS_MTU_STATE event=valid resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS}"`,
		`MTU_REMOVED_SERVER_LOG_FORMAT = "WHITEDNS_MTU_STATE event=removed resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS} cause={CAUSE}"`,
		`MTU_ADDED_SERVER_LOG_FORMAT = "WHITEDNS_MTU_STATE event=added resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS}"`,
	} {
		if !strings.Contains(toml, line) {
			t.Fatalf("runtime TOML missing %q:\n%s", line, toml)
		}
	}

	exported := RenderExportClientTOML(settings)
	if strings.Contains(exported, `/tmp/.wd-123.mtu-resolvers.log`) {
		t.Fatalf("exported TOML should not include runtime resolver state file:\n%s", exported)
	}
}

func TestRenderMasterDNSClientTOMLOmitsStormDNSRuntimeKeys(t *testing.T) {
	settings := model.DefaultSettingsProfile()
	settings.MTUTestParallelismResolvers = 77
	settings.MTUTestParallelismLogs = 13
	toml := RenderExportClientTOML(settings)

	if !strings.Contains(toml, `MTU_TEST_PARALLELISM = 77`) {
		t.Fatalf("MasterDNS TOML should use resolver MTU parallelism for MTU_TEST_PARALLELISM:\n%s", toml)
	}

	for _, line := range []string{
		`STARTUP_MODE =`,
		`LOG_TO_FILE =`,
		`LOG_DIR =`,
		`LOG_SCAN_`,
		`LOG_BASED_MTU_VERIFY =`,
		`PING_WATCHDOG_TIMEOUT_SECONDS =`,
		`TX_CHANNEL_SIZE =`,
		`UPLOAD_PACKET_DUPLICATION_COUNT =`,
		`MTU_TEST_RETRIES_RESOLVERS =`,
	} {
		if strings.Contains(toml, line) {
			t.Fatalf("MasterDNS TOML should omit %q:\n%s", line, toml)
		}
	}
}

func TestBuildLaunchConfigRejectsMissingInputs(t *testing.T) {
	state := model.DefaultAppState()
	if _, err := BuildLaunchConfig(state); err == nil {
		t.Fatal("expected missing domain/key error")
	}
}

func TestBuildLaunchConfigConvertsLegacyStormDNSConnectionForMasterDNSLaunch(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].EncryptionKey = "key"
	state.ConnectionProfiles[0].Name = "Legacy route"
	state.ConnectionProfiles[0].ImportType = model.ImportTypeStormDNS
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"

	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatalf("expected legacy StormDNS connection to be converted for launch, got %v", err)
	}
	if cfg.Connection.ImportType != model.ImportTypeMasterDNS {
		t.Fatalf("expected launch connection to use MasterDNS import type: %#v", cfg.Connection)
	}
}

func TestBuildLaunchConfigConvertsLegacyStormDNSSettingsForMasterDNSLaunch(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].EncryptionKey = "key"
	state.ConnectionProfiles[0].ImportType = model.ImportTypeMasterDNS
	state.ResolverProfiles[0].ResolverText = "1.1.1.1"
	stormSettings := model.DefaultSettingsProfile()
	stormSettings.ID = "settings-storm"
	stormSettings.Name = "StormDNS"
	stormSettings.ImportType = model.ImportTypeStormDNS
	state.SettingsProfiles = append(state.SettingsProfiles, stormSettings)
	state.SelectedSettingsProfileID = stormSettings.ID
	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatalf("expected legacy StormDNS settings to be converted for launch, got %v", err)
	}
	if cfg.Settings.ImportType != model.ImportTypeMasterDNS || cfg.MasterDNSSettings.ImportType != model.ImportTypeMasterDNS {
		t.Fatalf("expected launch settings to use MasterDNS import type: %#v / %#v", cfg.Settings, cfg.MasterDNSSettings)
	}
}

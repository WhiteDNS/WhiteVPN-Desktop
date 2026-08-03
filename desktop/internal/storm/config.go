package storm

import (
	"fmt"
	"os"
	"strings"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/resolver"
	"whitevpn-desktop/internal/xray"
)

type LaunchConfig struct {
	Connection         model.ConnectionProfile `json:"connection"`
	Resolver           model.ResolverProfile   `json:"resolver"`
	Settings           model.SettingsProfile   `json:"settings"`
	MasterDNSSettings  model.SettingsProfile   `json:"masterDnsSettings"`
	FullInitialMTUScan bool                    `json:"fullInitialMtuScan"`
	SkipInitialMTUScan bool                    `json:"skipInitialMtuScan"`
	CoreEnabled        bool                    `json:"singBoxEnabled"`
	CoreConfig         string                  `json:"singBoxConfig"`
	CoreProtocol       string                  `json:"coreProtocol"`
	SetSystemProxy     bool                    `json:"setSystemProxy"`
	PublicListenIP     string                  `json:"publicListenIp"`
	PublicListenPort   int                     `json:"publicListenPort"`
	ClientTOML         string                  `json:"clientToml"`
	Resolvers          string                  `json:"resolvers"`
	ResolversPath      string                  `json:"resolversPath"`
}

const (
	AppMTUResolverStateSuccessFormat       = "WHITEDNS_MTU_STATE event=valid resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS}"
	AppMTUResolverStateRemovedFormat       = "WHITEDNS_MTU_STATE event=removed resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS} cause={CAUSE}"
	AppMTUResolverStateAddedFormat         = "WHITEDNS_MTU_STATE event=added resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS}"
	AppMTUResolverStateReactiveAddedFormat = "WHITEDNS_MTU_STATE event=added resolver={IP} domain={DOMAIN} up={UP_MTU} down={DOWN_MTU} up_chars={UP_MTU_CHARS}"
	AppMTUResolverStateSeparatorFormat     = "WHITEDNS_MTU_STATE event=using"
)

func BuildLaunchConfig(state model.AppState) (LaunchConfig, error) {
	state = profiles.NormalizeState(state)
	settings, ok := SelectedSettings(state)
	if !ok {
		return LaunchConfig{}, fmt.Errorf("settings profile is missing")
	}
	return buildLaunchConfig(state, settings)
}

func BuildLaunchConfigWithSettings(state model.AppState, settings model.SettingsProfile) (LaunchConfig, error) {
	state = profiles.NormalizeState(state)
	return buildLaunchConfig(state, settings)
}

func buildLaunchConfig(state model.AppState, settings model.SettingsProfile) (LaunchConfig, error) {
	connection, ok := SelectedConnection(state)
	if !ok {
		return LaunchConfig{}, fmt.Errorf("connection profile is missing")
	}
	resolverProfile, ok := SelectedResolver(state)
	if !ok {
		return LaunchConfig{}, fmt.Errorf("resolver profile is missing")
	}
	if strings.TrimSpace(connection.Domain) == "" {
		return LaunchConfig{}, fmt.Errorf("MasterDNS/StormDNS domain is required")
	}
	if strings.TrimSpace(connection.EncryptionKey) == "" {
		return LaunchConfig{}, fmt.Errorf("MasterDNS/StormDNS encryption key is required")
	}
	connection.ImportType = model.ImportTypeMasterDNS
	resolversText := ""
	resolversPath := ""
	if strings.EqualFold(strings.TrimSpace(resolverProfile.ResolverSource), "file") {
		resolversPath = strings.TrimSpace(resolverProfile.ResolverFile)
		if resolversPath == "" {
			return LaunchConfig{}, fmt.Errorf("resolver file is missing")
		}
		info, err := os.Stat(resolversPath)
		if err != nil || info.IsDir() {
			return LaunchConfig{}, fmt.Errorf("resolver file is unavailable")
		}
		if resolverProfile.ResolverCount <= 0 {
			return LaunchConfig{}, fmt.Errorf("at least one resolver is required")
		}
	} else {
		resolverValidation := resolver.ValidateText(resolverProfile.ResolverText)
		if !resolverValidation.IsValid {
			if len(resolverValidation.InvalidEntries) > 0 {
				return LaunchConfig{}, fmt.Errorf("resolver list contains invalid entries")
			}
			return LaunchConfig{}, fmt.Errorf("at least one resolver is required")
		}
		resolversText = resolverValidation.NormalizedText
	}

	settings.ImportType = model.ImportTypeMasterDNS
	settings = profiles.NormalizeSettingsProfile(settings)
	masterDNSSettings := xray.MasterDNSSettings(settings)
	publicIP, publicPort := xray.PublicListen(settings)
	coreConfig, err := xray.RenderConfig(settings)
	if err != nil {
		return LaunchConfig{}, err
	}
	return LaunchConfig{
		Connection:         connection,
		Resolver:           resolverProfile,
		Settings:           settings,
		MasterDNSSettings:  masterDNSSettings,
		FullInitialMTUScan: settings.ConnectionStartupMode == model.ConnectionStartupModeFullScan,
		CoreEnabled:        xray.Enabled(settings),
		CoreConfig:         coreConfig,
		CoreProtocol:       xray.PublicProtocol(settings.SingBoxInboundType),
		SetSystemProxy:     settings.SingBoxSetSystemProxy,
		PublicListenIP:     publicIP,
		PublicListenPort:   publicPort,
		ClientTOML:         RenderClientTOML(connection, masterDNSSettings),
		Resolvers:          resolversText,
		ResolversPath:      resolversPath,
	}, nil
}

func SelectedConnection(state model.AppState) (model.ConnectionProfile, bool) {
	for _, profile := range state.ConnectionProfiles {
		if profile.ID == state.SelectedConnectionProfileID {
			return profile, true
		}
	}
	return model.ConnectionProfile{}, false
}

func SelectedResolver(state model.AppState) (model.ResolverProfile, bool) {
	connection, ok := SelectedConnection(state)
	resolverID := state.SelectedResolverProfileID
	if ok && connection.ResolverProfileID != "" {
		resolverID = connection.ResolverProfileID
	}
	for _, profile := range state.ResolverProfiles {
		if profile.ID == resolverID {
			return profile, true
		}
	}
	return model.ResolverProfile{}, false
}

func SelectedSettings(state model.AppState) (model.SettingsProfile, bool) {
	for _, profile := range state.SettingsProfiles {
		if profile.ID == state.SelectedSettingsProfileID {
			return profile, true
		}
	}
	return model.SettingsProfile{}, false
}

func RenderClientTOML(connection model.ConnectionProfile, settings model.SettingsProfile) string {
	settings = profiles.NormalizeSettingsProfile(settings)
	if model.NormalizeImportType(settings.ImportType) == model.ImportTypeStormDNS {
		return renderStormDNSClientTOML(connection, settings, true)
	}
	return renderMasterDNSClientTOML(connection, settings, true)
}

func RenderRuntimeClientTOML(connection model.ConnectionProfile, settings model.SettingsProfile, mtuResolverStateFile string) string {
	settings = profiles.NormalizeSettingsProfile(settings)
	if strings.TrimSpace(mtuResolverStateFile) != "" {
		settings.SaveMTUServersToFile = true
		settings.MTUServersFileName = mtuResolverStateFile
		settings.MTUServersFileFormat = AppMTUResolverStateSuccessFormat
		settings.MTUUsingSectionSeparatorText = AppMTUResolverStateSeparatorFormat
		settings.MTURemovedServerLogFormat = AppMTUResolverStateRemovedFormat
		settings.MTUAddedServerLogFormat = AppMTUResolverStateAddedFormat
		settings.MTUReactiveAddedServerLogFormat = AppMTUResolverStateReactiveAddedFormat
	}
	return renderMasterDNSClientTOML(connection, settings, true)
}

func RenderExportClientTOML(settings model.SettingsProfile) string {
	settings = profiles.NormalizeSettingsProfile(settings)
	if model.NormalizeImportType(settings.ImportType) == model.ImportTypeStormDNS {
		return renderStormDNSClientTOML(model.ConnectionProfile{}, xray.MasterDNSSettings(settings), false)
	}
	return renderMasterDNSClientTOML(model.ConnectionProfile{}, xray.MasterDNSSettings(settings), false)
}

func renderStormDNSClientTOML(connection model.ConnectionProfile, settings model.SettingsProfile, includeConnection bool) string {
	settings = profiles.NormalizeSettingsProfile(settings)

	var b strings.Builder
	linef := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	linef("# WHITEDNS_IMPORT_TYPE = \"%s\"", model.ImportTypeStormDNS)
	if includeConnection {
		domain := strings.TrimSpace(strings.TrimSuffix(connection.Domain, "."))
		key := strings.TrimSpace(connection.EncryptionKey)
		method := connection.EncryptionMethod
		if method < 0 || method > 5 {
			method = 1
		}
		linef("DOMAINS = [\"%s\"]", escape(domain))
		linef("DATA_ENCRYPTION_METHOD = %d", method)
		linef("ENCRYPTION_KEY = \"%s\"", escape(key))
	}
	linef("PROTOCOL_TYPE = \"SOCKS5\"")
	linef("LISTEN_IP = \"%s\"", escape(settings.ListenIP))
	linef("LISTEN_PORT = %d", settings.ListenPort)
	linef("SOCKS5_AUTH = %t", settings.SOCKS5Authentication)
	linef("SOCKS5_USER = \"%s\"", escape(settings.SOCKSUsername))
	linef("SOCKS5_PASS = \"%s\"", escape(settings.SOCKSPassword))
	linef("LOCAL_DNS_ENABLED = %t", settings.LocalDNSEnabled)
	linef("LOCAL_DNS_IP = \"127.0.0.1\"")
	linef("LOCAL_DNS_PORT = %d", settings.LocalDNSPort)
	linef("RESOLVER_BALANCING_STRATEGY = %d", settings.BalancingStrategy)
	linef("UPLOAD_PACKET_DUPLICATION_COUNT = %d", settings.UploadDuplication)
	linef("DOWNLOAD_PACKET_DUPLICATION_COUNT = %d", settings.DownloadDuplication)
	linef("UPLOAD_COMPRESSION_TYPE = %d", settings.UploadCompression)
	linef("DOWNLOAD_COMPRESSION_TYPE = %d", settings.DownloadCompression)
	linef("BASE_ENCODE_DATA = %t", settings.BaseEncodeData)
	linef("MIN_UPLOAD_MTU = %d", settings.MinUploadMTU)
	linef("MIN_DOWNLOAD_MTU = %d", settings.MinDownloadMTU)
	linef("MAX_UPLOAD_MTU = %d", settings.MaxUploadMTU)
	linef("MAX_DOWNLOAD_MTU = %d", settings.MaxDownloadMTU)
	linef("MTU_TEST_RETRIES_RESOLVERS = %d", settings.MTUTestRetriesResolvers)
	linef("MTU_TEST_TIMEOUT_RESOLVERS = %.3g", settings.MTUTestTimeoutResolvers)
	linef("MTU_TEST_PARALLELISM_RESOLVERS = %d", settings.MTUTestParallelismResolvers)
	linef("MTU_TEST_RETRIES_LOGS = %d", settings.MTUTestRetriesLogs)
	linef("MTU_TEST_TIMEOUT_LOGS = %.3g", settings.MTUTestTimeoutLogs)
	linef("MTU_TEST_PARALLELISM_LOGS = %d", settings.MTUTestParallelismLogs)
	linef("RX_TX_WORKERS = %d", settings.RXTXWorkers)
	linef("TUNNEL_PROCESS_WORKERS = %d", settings.TunnelProcessWorkers)
	linef("TUNNEL_PACKET_TIMEOUT_SECONDS = %.3g", settings.TunnelPacketTimeoutSeconds)
	linef("DISPATCHER_IDLE_POLL_INTERVAL_SECONDS = %.3g", settings.DispatcherIdlePollIntervalSec)
	linef("TX_CHANNEL_SIZE = %d", settings.TXChannelSize)
	linef("RX_CHANNEL_SIZE = %d", settings.RXChannelSize)
	linef("RESOLVER_UDP_CONNECTION_POOL_SIZE = %d", settings.ResolverUDPConnectionPoolSize)
	linef("STREAM_QUEUE_INITIAL_CAPACITY = %d", settings.StreamQueueInitialCapacity)
	linef("ORPHAN_QUEUE_INITIAL_CAPACITY = %d", settings.OrphanQueueInitialCapacity)
	linef("DNS_RESPONSE_FRAGMENT_STORE_CAPACITY = %d", settings.DNSResponseFragmentStoreCapacity)
	linef("MAX_ACTIVE_STREAMS = %d", settings.MaxActiveStreams)
	linef("LOCAL_HANDSHAKE_TIMEOUT_SECONDS = %.3g", settings.LocalHandshakeTimeoutSeconds)
	linef("SOCKS_UDP_ASSOCIATE_READ_TIMEOUT_SECONDS = %.3g", settings.SOCKSUDPAssociateReadTimeoutSec)
	linef("CLIENT_TERMINAL_STREAM_RETENTION_SECONDS = %.3g", settings.ClientTerminalStreamRetentionSec)
	linef("CLIENT_CANCELLED_SETUP_RETENTION_SECONDS = %.3g", settings.ClientCancelledSetupRetentionSec)
	linef("SESSION_INIT_RETRY_BASE_SECONDS = %.3g", settings.SessionInitRetryBaseSeconds)
	linef("SESSION_INIT_RETRY_STEP_SECONDS = %.3g", settings.SessionInitRetryStepSeconds)
	linef("SESSION_INIT_RETRY_LINEAR_AFTER = %d", settings.SessionInitRetryLinearAfter)
	linef("SESSION_INIT_RETRY_MAX_SECONDS = %.3g", settings.SessionInitRetryMaxSeconds)
	linef("SESSION_INIT_BUSY_RETRY_INTERVAL_SECONDS = %.3g", settings.SessionInitBusyRetryIntervalSec)
	linef("STARTUP_MODE = \"%s\"", escape(settings.StartupMode))
	linef("LOG_SCAN_MAX_DAYS = 14")
	linef("LOG_SCAN_MAX_RESOLVERS = 128")
	linef("LOG_BASED_MTU_VERIFY = true")
	linef("STATS_REPORT_INTERVAL_SECONDS = 1.0")
	linef("PING_WATCHDOG_TIMEOUT_SECONDS = %d", settings.PingWatchdogSeconds)
	linef("LOG_LEVEL = \"%s\"", escape(settings.LogLevel))
	linef("LOG_TO_FILE = true")
	linef("LOG_DIR = \"logs\"")
	return strings.TrimRight(b.String(), "\n")
}

func renderMasterDNSClientTOML(connection model.ConnectionProfile, settings model.SettingsProfile, includeConnection bool) string {
	settings = profiles.NormalizeSettingsProfile(settings)

	var b strings.Builder
	linef := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	linef("# WHITEDNS_IMPORT_TYPE = \"%s\"", model.ImportTypeMasterDNS)
	if includeConnection {
		domain := strings.TrimSpace(strings.TrimSuffix(connection.Domain, "."))
		key := strings.TrimSpace(connection.EncryptionKey)
		method := connection.EncryptionMethod
		if method < 0 || method > 5 {
			method = 1
		}
		linef("DOMAINS = [\"%s\"]", escape(domain))
		linef("DATA_ENCRYPTION_METHOD = %d", method)
		linef("ENCRYPTION_KEY = \"%s\"", escape(key))
	}
	linef("PROTOCOL_TYPE = \"SOCKS5\"")
	linef("LISTEN_IP = \"%s\"", escape(settings.ListenIP))
	linef("LISTEN_PORT = %d", settings.ListenPort)
	linef("SOCKS5_AUTH = %t", settings.SOCKS5Authentication)
	linef("SOCKS5_USER = \"%s\"", escape(settings.SOCKSUsername))
	linef("SOCKS5_PASS = \"%s\"", escape(settings.SOCKSPassword))
	linef("LOCAL_DNS_ENABLED = %t", settings.LocalDNSEnabled)
	linef("LOCAL_DNS_IP = \"127.0.0.1\"")
	linef("LOCAL_DNS_PORT = %d", settings.LocalDNSPort)
	linef("LOCAL_DNS_CACHE_MAX_RECORDS = 10000")
	linef("LOCAL_DNS_CACHE_TTL_SECONDS = 14400.0")
	linef("LOCAL_DNS_PENDING_TIMEOUT_SECONDS = 300.0")
	linef("DNS_RESPONSE_FRAGMENT_TIMEOUT_SECONDS = 60.0")
	linef("LOCAL_DNS_CACHE_PERSIST_TO_FILE = true")
	linef("LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS = 60.0")
	linef("RESOLVER_BALANCING_STRATEGY = %d", settings.BalancingStrategy)
	linef("PACKET_DUPLICATION_COUNT = %d", masterDNSClientDuplicationCount(settings.UploadDuplication))
	linef("SETUP_PACKET_DUPLICATION_COUNT = %d", masterDNSClientDuplicationCount(settings.DownloadDuplication))
	linef("STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD = 2")
	linef("STREAM_RESOLVER_FAILOVER_COOLDOWN = 2.5")
	linef("RECHECK_INACTIVE_SERVERS_ENABLED = true")
	linef("AUTO_DISABLE_TIMEOUT_SERVERS = true")
	linef("AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS = 30.0")
	linef("BASE_ENCODE_DATA = %t", settings.BaseEncodeData)
	linef("UPLOAD_COMPRESSION_TYPE = %d", settings.UploadCompression)
	linef("DOWNLOAD_COMPRESSION_TYPE = %d", settings.DownloadCompression)
	linef("COMPRESSION_MIN_SIZE = 120")
	linef("MIN_UPLOAD_MTU = %d", settings.MinUploadMTU)
	linef("MIN_DOWNLOAD_MTU = %d", settings.MinDownloadMTU)
	linef("MAX_UPLOAD_MTU = %d", settings.MaxUploadMTU)
	linef("MAX_DOWNLOAD_MTU = %d", settings.MaxDownloadMTU)
	linef("AUTO_REMOVE_LOW_MTU_SERVERS = %t", settings.AutoRemoveLowMTUServers)
	linef("MTU_TEST_RETRIES = %d", settings.MTUTestRetriesResolvers)
	linef("MTU_TEST_TIMEOUT = %.3g", settings.MTUTestTimeoutResolvers)
	linef("MTU_TEST_PARALLELISM = %d", settings.MTUTestParallelismResolvers)
	linef("MTU_STARTUP_LOSS_VERIFY_ENABLED = %t", settings.MTUStartupLossVerifyEnabled)
	linef("MTU_STARTUP_LOSS_VERIFY_SAMPLES = %d", settings.MTUStartupLossVerifySamples)
	linef("MTU_STARTUP_LOSS_VERIFY_MAX_LOSS_PERCENT = %d", settings.MTUStartupLossVerifyMaxLossPct)
	linef("MTU_STARTUP_LOSS_VERIFY_CANDIDATES = %d", settings.MTUStartupLossVerifyCandidates)
	linef("MTU_RECHECK_ENABLED = %t", settings.MTURecheckEnabled)
	linef("MTU_RECHECK_INTERVAL_MINUTES = %d", settings.MTURecheckIntervalMinutes)
	linef("SAVE_MTU_SERVERS_TO_FILE = %t", settings.SaveMTUServersToFile)
	linef("MTU_SERVERS_FILE_NAME = \"%s\"", escape(settings.MTUServersFileName))
	linef("MTU_SERVERS_FILE_FORMAT = \"%s\"", escape(settings.MTUServersFileFormat))
	linef("MTU_USING_SECTION_SEPARATOR_TEXT = \"%s\"", escape(settings.MTUUsingSectionSeparatorText))
	linef("MTU_REMOVED_SERVER_LOG_FORMAT = \"%s\"", escape(settings.MTURemovedServerLogFormat))
	linef("MTU_ADDED_SERVER_LOG_FORMAT = \"%s\"", escape(settings.MTUAddedServerLogFormat))
	linef("MTU_REACTIVE_ADDED_SERVER_LOG_FORMAT = \"%s\"", escape(settings.MTUReactiveAddedServerLogFormat))
	linef("RX_TX_WORKERS = %d", settings.RXTXWorkers)
	linef("TUNNEL_PROCESS_WORKERS = %d", settings.TunnelProcessWorkers)
	linef("TUNNEL_PACKET_TIMEOUT_SECONDS = %.3g", settings.TunnelPacketTimeoutSeconds)
	linef("DISPATCHER_IDLE_POLL_INTERVAL_SECONDS = %.3g", settings.DispatcherIdlePollIntervalSec)
	linef("RX_CHANNEL_SIZE = %d", settings.RXChannelSize)
	linef("SOCKS_UDP_ASSOCIATE_READ_TIMEOUT_SECONDS = %.3g", settings.SOCKSUDPAssociateReadTimeoutSec)
	linef("CLIENT_TERMINAL_STREAM_RETENTION_SECONDS = %.3g", settings.ClientTerminalStreamRetentionSec)
	linef("CLIENT_CANCELLED_SETUP_RETENTION_SECONDS = %.3g", settings.ClientCancelledSetupRetentionSec)
	linef("SESSION_INIT_RETRY_BASE_SECONDS = %.3g", settings.SessionInitRetryBaseSeconds)
	linef("SESSION_INIT_RETRY_STEP_SECONDS = %.3g", settings.SessionInitRetryStepSeconds)
	linef("SESSION_INIT_RETRY_LINEAR_AFTER = %d", settings.SessionInitRetryLinearAfter)
	linef("SESSION_INIT_RETRY_MAX_SECONDS = %.3g", settings.SessionInitRetryMaxSeconds)
	linef("SESSION_INIT_BUSY_RETRY_INTERVAL_SECONDS = %.3g", settings.SessionInitBusyRetryIntervalSec)
	linef("SESSION_INIT_RACING_COUNT = %d", settings.SessionInitRacingCount)
	linef("PING_AGGRESSIVE_INTERVAL_SECONDS = 0.100")
	linef("PING_LAZY_INTERVAL_SECONDS = 0.750")
	linef("PING_COOLDOWN_INTERVAL_SECONDS = 2.0")
	linef("PING_COLD_INTERVAL_SECONDS = 15.0")
	linef("PING_WARM_THRESHOLD_SECONDS = 8.0")
	linef("PING_COOL_THRESHOLD_SECONDS = 20.0")
	linef("PING_COLD_THRESHOLD_SECONDS = 30.0")
	linef("MAX_PACKETS_PER_BATCH = 8")
	linef("ARQ_WINDOW_SIZE = 1000")
	linef("ARQ_INITIAL_RTO_SECONDS = 0.5")
	linef("ARQ_MAX_RTO_SECONDS = 3.0")
	linef("ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.5")
	linef("ARQ_CONTROL_MAX_RTO_SECONDS = 2.0")
	linef("ARQ_MAX_CONTROL_RETRIES = 126")
	linef("ARQ_INACTIVITY_TIMEOUT_SECONDS = 1800.0")
	linef("ARQ_DATA_PACKET_TTL_SECONDS = 2400.0")
	linef("ARQ_CONTROL_PACKET_TTL_SECONDS = 1200.0")
	linef("ARQ_MAX_DATA_RETRIES = 126")
	linef("ARQ_DATA_NACK_MAX_GAP = 32")
	linef("ARQ_DATA_NACK_INITIAL_DELAY_SECONDS = 0.1")
	linef("ARQ_DATA_NACK_REPEAT_SECONDS = 0.8")
	linef("ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS = 120.0")
	linef("ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS = 90.0")
	linef("STATS_REPORT_INTERVAL_SECONDS = 1.0")
	linef("LOG_LEVEL = \"%s\"", escape(settings.LogLevel))
	return strings.TrimRight(b.String(), "\n")
}

func escape(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func masterDNSClientDuplicationCount(value int) int {
	if value < 1 {
		return 1
	}
	return value
}

package storm

import (
	"fmt"
	"strings"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func RenderScannerClientTOML(connection model.ConnectionProfile, listenPort int, apiPort int, scanParallel int) string {
	return renderScannerClientTOML(connection, listenPort, apiPort, scanParallel, 30, 40)
}

func RenderConnectionUpgradeScannerClientTOML(connection model.ConnectionProfile, settings model.SettingsProfile, listenPort int, apiPort int, scanParallel int) string {
	settings = profiles.NormalizeSettingsProfile(settings)
	return renderScannerClientTOML(connection, listenPort, apiPort, scanParallel, settings.MinUploadMTU, settings.MinDownloadMTU)
}

func renderScannerClientTOML(connection model.ConnectionProfile, listenPort int, apiPort int, scanParallel int, uploadMTU int, downloadMTU int) string {
	domain := strings.TrimSpace(strings.TrimSuffix(connection.Domain, "."))
	key := strings.TrimSpace(connection.EncryptionKey)
	method := connection.EncryptionMethod
	if method < 0 || method > 5 {
		method = 1
	}
	if listenPort <= 0 || listenPort > 65535 {
		listenPort = 18000
	}
	if apiPort <= 0 || apiPort > 65535 {
		apiPort = 9157
	}
	if scanParallel < 1 {
		scanParallel = 200
	}
	if scanParallel > 1000 {
		scanParallel = 1000
	}
	if uploadMTU <= 0 {
		uploadMTU = 30
	}
	if downloadMTU <= 0 {
		downloadMTU = 40
	}

	var b strings.Builder
	linef := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}

	linef("# WHITEDNS_IMPORT_TYPE = \"masterdns\"")
	linef("DOMAINS = [\"%s\"]", escape(domain))
	linef("DATA_ENCRYPTION_METHOD = %d", method)
	linef("ENCRYPTION_KEY = \"%s\"", escape(key))
	linef("PROTOCOL_TYPE = \"SOCKS5\"")
	linef("LISTEN_IP = \"127.0.0.1\"")
	linef("LISTEN_PORT = %d", listenPort)
	linef("SOCKS5_AUTH = false")
	linef("SOCKS5_USER = \"master_dns_vpn\"")
	linef("SOCKS5_PASS = \"master_dns_vpn\"")
	linef("LOCAL_DNS_ENABLED = false")
	linef("LOCAL_DNS_IP = \"127.0.0.1\"")
	linef("LOCAL_DNS_PORT = 53")
	linef("LOCAL_DNS_CACHE_MAX_RECORDS = 10000")
	linef("LOCAL_DNS_CACHE_TTL_SECONDS = 14400.0")
	linef("LOCAL_DNS_PENDING_TIMEOUT_SECONDS = 300.0")
	linef("DNS_RESPONSE_FRAGMENT_TIMEOUT_SECONDS = 60.0")
	linef("LOCAL_DNS_CACHE_PERSIST_TO_FILE = true")
	linef("LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS = 60.0")
	linef("RESOLVER_BALANCING_STRATEGY = 3")
	linef("PACKET_DUPLICATION_COUNT = 1")
	linef("SETUP_PACKET_DUPLICATION_COUNT = 3")
	linef("STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD = 2")
	linef("STREAM_RESOLVER_FAILOVER_COOLDOWN = 2.5")
	linef("RECHECK_INACTIVE_SERVERS_ENABLED = true")
	linef("AUTO_DISABLE_TIMEOUT_SERVERS = true")
	linef("AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS = 30.0")
	linef("BASE_ENCODE_DATA = false")
	linef("UPLOAD_COMPRESSION_TYPE = 0")
	linef("DOWNLOAD_COMPRESSION_TYPE = 0")
	linef("COMPRESSION_MIN_SIZE = 120")
	linef("MIN_UPLOAD_MTU = %d", uploadMTU)
	linef("MIN_DOWNLOAD_MTU = %d", downloadMTU)
	linef("MAX_UPLOAD_MTU = %d", uploadMTU)
	linef("MAX_DOWNLOAD_MTU = %d", downloadMTU)
	linef("AUTO_REMOVE_LOW_MTU_SERVERS = false")
	linef("MTU_TEST_RETRIES = 1")
	linef("MTU_TEST_TIMEOUT = 1.0")
	linef("MTU_TEST_PARALLELISM = %d", scanParallel)
	linef("SAVE_MTU_SERVERS_TO_FILE = false")
	linef("MTU_SERVERS_FILE_NAME = \"masterdnsvpn_success_test_{time}.log\"")
	linef("MTU_SERVERS_FILE_FORMAT = \"{IP} ({DOMAIN}) - UP: {UP_MTU} DOWN: {DOWN-MTU}\"")
	linef("MTU_USING_SECTION_SEPARATOR_TEXT = \"\"")
	linef("MTU_REMOVED_SERVER_LOG_FORMAT = \"Resolver {IP} ({DOMAIN}) removed at {TIME} due to {CAUSE}\"")
	linef("MTU_ADDED_SERVER_LOG_FORMAT = \"Resolver {IP} ({DOMAIN}) added back at {TIME} (UP {UP_MTU}, DOWN {DOWN_MTU})\"")
	linef("MTU_REACTIVE_ADDED_SERVER_LOG_FORMAT = \"Resolver {IP} ({DOMAIN}) added back at {TIME} after reactive recheck (UP {UP_MTU}, DOWN {DOWN_MTU})\"")
	linef("RX_TX_WORKERS = 4")
	linef("TUNNEL_PROCESS_WORKERS = 6")
	linef("TUNNEL_PACKET_TIMEOUT_SECONDS = 10.0")
	linef("DISPATCHER_IDLE_POLL_INTERVAL_SECONDS = 0.020")
	linef("RX_CHANNEL_SIZE = 4096")
	linef("SOCKS_UDP_ASSOCIATE_READ_TIMEOUT_SECONDS = 30.0")
	linef("CLIENT_TERMINAL_STREAM_RETENTION_SECONDS = 45.0")
	linef("CLIENT_CANCELLED_SETUP_RETENTION_SECONDS = 120.0")
	linef("SESSION_INIT_RETRY_BASE_SECONDS = 1.0")
	linef("SESSION_INIT_RETRY_STEP_SECONDS = 1.0")
	linef("SESSION_INIT_RETRY_LINEAR_AFTER = 5")
	linef("SESSION_INIT_RETRY_MAX_SECONDS = 60.0")
	linef("SESSION_INIT_BUSY_RETRY_INTERVAL_SECONDS = 60.0")
	linef("SESSION_INIT_RACING_COUNT = 3")
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
	linef("LOG_LEVEL = \"INFO\"")
	return strings.TrimRight(b.String(), "\n")
}

package storm

import (
	"bufio"
	"fmt"
	"math"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func ParseSettingsProfileTOML(rawText, suggestedName string, importType string) (model.SettingsProfile, error) {
	values, err := parseFlatTOML(rawText)
	if err != nil {
		return model.SettingsProfile{}, err
	}
	if len(values) == 0 {
		return model.SettingsProfile{}, fmt.Errorf("TOML settings are empty")
	}

	profile := model.DefaultSettingsProfile()
	profile.ID = ""
	profile.Name = cleanImportedSettingsName(suggestedName)
	profile.ImportType = detectSettingsImportType(rawText, importType)

	applied := 0
	setString := func(key string, apply func(string)) error {
		raw, ok := values[key]
		if !ok {
			return nil
		}
		value, err := parseTOMLString(raw)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		apply(value)
		applied++
		return nil
	}
	setBool := func(key string, apply func(bool)) error {
		raw, ok := values[key]
		if !ok {
			return nil
		}
		value, err := parseTOMLBool(raw)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		apply(value)
		applied++
		return nil
	}
	setInt := func(key string, apply func(int)) error {
		raw, ok := values[key]
		if !ok {
			return nil
		}
		value, err := parseTOMLInt(raw)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		apply(value)
		applied++
		return nil
	}
	setFloat := func(key string, apply func(float64)) error {
		raw, ok := values[key]
		if !ok {
			return nil
		}
		value, err := parseTOMLFloat(raw)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		apply(value)
		applied++
		return nil
	}

	for _, apply := range []func() error{
		func() error { return setString("LISTEN_IP", func(value string) { profile.StormDNSListenIP = value }) },
		func() error { return setInt("LISTEN_PORT", func(value int) { profile.StormDNSListenPort = value }) },
		func() error { return setBool("SOCKS5_AUTH", func(value bool) { profile.SOCKS5Authentication = value }) },
		func() error { return setString("SOCKS5_USER", func(value string) { profile.SOCKSUsername = value }) },
		func() error { return setString("SOCKS5_PASS", func(value string) { profile.SOCKSPassword = value }) },
		func() error {
			return setBool("LOCAL_DNS_ENABLED", func(value bool) { profile.LocalDNSEnabled = value })
		},
		func() error { return setInt("LOCAL_DNS_PORT", func(value int) { profile.LocalDNSPort = value }) },
		func() error {
			return setInt("RESOLVER_BALANCING_STRATEGY", func(value int) { profile.BalancingStrategy = value })
		},
		func() error {
			return setInt("UPLOAD_PACKET_DUPLICATION_COUNT", func(value int) { profile.UploadDuplication = value })
		},
		func() error {
			return setInt("DOWNLOAD_PACKET_DUPLICATION_COUNT", func(value int) { profile.DownloadDuplication = value })
		},
		func() error {
			return setInt("PACKET_DUPLICATION_COUNT", func(value int) { profile.UploadDuplication = value })
		},
		func() error {
			return setInt("SETUP_PACKET_DUPLICATION_COUNT", func(value int) { profile.DownloadDuplication = value })
		},
		func() error {
			return setBool("AUTO_REMOVE_LOW_MTU_SERVERS", func(value bool) { profile.AutoRemoveLowMTUServers = value })
		},
		func() error {
			return setInt("UPLOAD_COMPRESSION_TYPE", func(value int) { profile.UploadCompression = value })
		},
		func() error {
			return setInt("DOWNLOAD_COMPRESSION_TYPE", func(value int) { profile.DownloadCompression = value })
		},
		func() error { return setBool("BASE_ENCODE_DATA", func(value bool) { profile.BaseEncodeData = value }) },
		func() error { return setInt("MIN_UPLOAD_MTU", func(value int) { profile.MinUploadMTU = value }) },
		func() error { return setInt("MIN_DOWNLOAD_MTU", func(value int) { profile.MinDownloadMTU = value }) },
		func() error { return setInt("MAX_UPLOAD_MTU", func(value int) { profile.MaxUploadMTU = value }) },
		func() error { return setInt("MAX_DOWNLOAD_MTU", func(value int) { profile.MaxDownloadMTU = value }) },
		func() error {
			return setInt("MTU_TEST_RETRIES_RESOLVERS", func(value int) { profile.MTUTestRetriesResolvers = value })
		},
		func() error {
			return setFloat("MTU_TEST_TIMEOUT_RESOLVERS", func(value float64) { profile.MTUTestTimeoutResolvers = value })
		},
		func() error {
			return setInt("MTU_TEST_PARALLELISM_RESOLVERS", func(value int) { profile.MTUTestParallelismResolvers = value })
		},
		func() error {
			return setInt("MTU_TEST_RETRIES_LOGS", func(value int) { profile.MTUTestRetriesLogs = value })
		},
		func() error {
			return setFloat("MTU_TEST_TIMEOUT_LOGS", func(value float64) { profile.MTUTestTimeoutLogs = value })
		},
		func() error {
			return setInt("MTU_TEST_PARALLELISM_LOGS", func(value int) { profile.MTUTestParallelismLogs = value })
		},
		func() error {
			return setInt("MTU_TEST_RETRIES", func(value int) {
				profile.MTUTestRetriesResolvers = value
				profile.MTUTestRetriesLogs = value
			})
		},
		func() error {
			return setFloat("MTU_TEST_TIMEOUT", func(value float64) {
				profile.MTUTestTimeoutResolvers = value
				profile.MTUTestTimeoutLogs = value
			})
		},
		func() error {
			return setInt("MTU_TEST_PARALLELISM", func(value int) {
				profile.MTUTestParallelismResolvers = value
				profile.MTUTestParallelismLogs = value
			})
		},
		func() error {
			return setBool("MTU_STARTUP_LOSS_VERIFY_ENABLED", func(value bool) { profile.MTUStartupLossVerifyEnabled = value })
		},
		func() error {
			return setInt("MTU_STARTUP_LOSS_VERIFY_SAMPLES", func(value int) { profile.MTUStartupLossVerifySamples = value })
		},
		func() error {
			return setInt("MTU_STARTUP_LOSS_VERIFY_MAX_LOSS_PERCENT", func(value int) { profile.MTUStartupLossVerifyMaxLossPct = value })
		},
		func() error {
			return setInt("MTU_STARTUP_LOSS_VERIFY_CANDIDATES", func(value int) { profile.MTUStartupLossVerifyCandidates = value })
		},
		func() error {
			return setBool("MTU_RECHECK_ENABLED", func(value bool) { profile.MTURecheckEnabled = value })
		},
		func() error {
			return setInt("MTU_RECHECK_INTERVAL_MINUTES", func(value int) { profile.MTURecheckIntervalMinutes = value })
		},
		func() error {
			return setBool("SAVE_MTU_SERVERS_TO_FILE", func(value bool) { profile.SaveMTUServersToFile = value })
		},
		func() error {
			return setString("MTU_SERVERS_FILE_NAME", func(value string) { profile.MTUServersFileName = value })
		},
		func() error {
			return setString("MTU_SERVERS_FILE_FORMAT", func(value string) { profile.MTUServersFileFormat = value })
		},
		func() error {
			return setString("MTU_USING_SECTION_SEPARATOR_TEXT", func(value string) { profile.MTUUsingSectionSeparatorText = value })
		},
		func() error {
			return setString("MTU_REMOVED_SERVER_LOG_FORMAT", func(value string) { profile.MTURemovedServerLogFormat = value })
		},
		func() error {
			return setString("MTU_ADDED_SERVER_LOG_FORMAT", func(value string) { profile.MTUAddedServerLogFormat = value })
		},
		func() error {
			return setString("MTU_REACTIVE_ADDED_SERVER_LOG_FORMAT", func(value string) { profile.MTUReactiveAddedServerLogFormat = value })
		},
		func() error { return setInt("RX_TX_WORKERS", func(value int) { profile.RXTXWorkers = value }) },
		func() error {
			return setInt("TUNNEL_PROCESS_WORKERS", func(value int) { profile.TunnelProcessWorkers = value })
		},
		func() error {
			return setFloat("TUNNEL_PACKET_TIMEOUT_SECONDS", func(value float64) { profile.TunnelPacketTimeoutSeconds = value })
		},
		func() error {
			return setFloat("DISPATCHER_IDLE_POLL_INTERVAL_SECONDS", func(value float64) { profile.DispatcherIdlePollIntervalSec = value })
		},
		func() error { return setInt("TX_CHANNEL_SIZE", func(value int) { profile.TXChannelSize = value }) },
		func() error { return setInt("RX_CHANNEL_SIZE", func(value int) { profile.RXChannelSize = value }) },
		func() error {
			return setInt("RESOLVER_UDP_CONNECTION_POOL_SIZE", func(value int) { profile.ResolverUDPConnectionPoolSize = value })
		},
		func() error {
			return setInt("STREAM_QUEUE_INITIAL_CAPACITY", func(value int) { profile.StreamQueueInitialCapacity = value })
		},
		func() error {
			return setInt("ORPHAN_QUEUE_INITIAL_CAPACITY", func(value int) { profile.OrphanQueueInitialCapacity = value })
		},
		func() error {
			return setInt("DNS_RESPONSE_FRAGMENT_STORE_CAPACITY", func(value int) { profile.DNSResponseFragmentStoreCapacity = value })
		},
		func() error {
			return setInt("MAX_ACTIVE_STREAMS", func(value int) { profile.MaxActiveStreams = value })
		},
		func() error {
			return setFloat("LOCAL_HANDSHAKE_TIMEOUT_SECONDS", func(value float64) { profile.LocalHandshakeTimeoutSeconds = value })
		},
		func() error {
			return setFloat("SOCKS_UDP_ASSOCIATE_READ_TIMEOUT_SECONDS", func(value float64) { profile.SOCKSUDPAssociateReadTimeoutSec = value })
		},
		func() error {
			return setFloat("CLIENT_TERMINAL_STREAM_RETENTION_SECONDS", func(value float64) { profile.ClientTerminalStreamRetentionSec = value })
		},
		func() error {
			return setFloat("CLIENT_CANCELLED_SETUP_RETENTION_SECONDS", func(value float64) { profile.ClientCancelledSetupRetentionSec = value })
		},
		func() error {
			return setFloat("SESSION_INIT_RETRY_BASE_SECONDS", func(value float64) { profile.SessionInitRetryBaseSeconds = value })
		},
		func() error {
			return setFloat("SESSION_INIT_RETRY_STEP_SECONDS", func(value float64) { profile.SessionInitRetryStepSeconds = value })
		},
		func() error {
			return setInt("SESSION_INIT_RETRY_LINEAR_AFTER", func(value int) { profile.SessionInitRetryLinearAfter = value })
		},
		func() error {
			return setFloat("SESSION_INIT_RETRY_MAX_SECONDS", func(value float64) { profile.SessionInitRetryMaxSeconds = value })
		},
		func() error {
			return setFloat("SESSION_INIT_BUSY_RETRY_INTERVAL_SECONDS", func(value float64) { profile.SessionInitBusyRetryIntervalSec = value })
		},
		func() error {
			return setInt("SESSION_INIT_RACING_COUNT", func(value int) { profile.SessionInitRacingCount = value })
		},
		func() error { return setString("STARTUP_MODE", func(value string) { profile.StartupMode = value }) },
		func() error {
			return setInt("PING_WATCHDOG_TIMEOUT_SECONDS", func(value int) { profile.PingWatchdogSeconds = value })
		},
		func() error { return setString("LOG_LEVEL", func(value string) { profile.LogLevel = value }) },
	} {
		if err := apply(); err != nil {
			return model.SettingsProfile{}, err
		}
	}

	if applied == 0 {
		return model.SettingsProfile{}, fmt.Errorf("TOML does not contain importable settings")
	}

	return profiles.NormalizeSettingsProfile(profile), nil
}

func detectSettingsImportType(rawText string, fallback string) string {
	scanner := bufio.NewScanner(strings.NewReader(rawText))
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "//"))
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "WHITEDNS_IMPORT_TYPE") || strings.EqualFold(strings.TrimSpace(key), "IMPORT_TYPE") {
			parsed, err := parseTOMLString(strings.TrimSpace(value))
			if err != nil {
				parsed = strings.Trim(strings.TrimSpace(value), `"'`)
			}
			return model.NormalizeImportType(parsed)
		}
	}
	return model.NormalizeImportType(fallback)
}

func cleanImportedSettingsName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".toml")
	name = strings.TrimSpace(name)
	if name == "" {
		return "Imported settings"
	}
	return name
}

func parseFlatTOML(rawText string) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(rawText))
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(stripTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			return nil, fmt.Errorf("TOML sections are not supported for settings import")
		}
		index := strings.Index(line, "=")
		if index <= 0 {
			return nil, fmt.Errorf("invalid TOML assignment on line %d", lineNumber)
		}
		key := strings.ToUpper(strings.TrimSpace(line[:index]))
		value := strings.TrimSpace(line[index+1:])
		if key == "" || value == "" {
			return nil, fmt.Errorf("invalid TOML assignment on line %d", lineNumber)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func stripTOMLComment(line string) string {
	inString := false
	var quote rune
	escaped := false
	for index, ch := range line {
		if inString {
			if quote == '"' && escaped {
				escaped = false
				continue
			}
			if quote == '"' && ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				inString = false
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inString = true
			quote = ch
			continue
		}
		if ch == '#' {
			return line[:index]
		}
	}
	return line
}

func parseTOMLString(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return strconv.Unquote(raw)
	}
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], nil
	}
	if strings.HasPrefix(raw, "[") {
		return "", fmt.Errorf("expected string")
	}
	return raw, nil
}

func parseTOMLBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean")
	}
}

func parseTOMLInt(raw string) (int, error) {
	value, err := parseTOMLFloat(raw)
	if err != nil {
		return 0, err
	}
	if math.Trunc(value) != value {
		return 0, fmt.Errorf("expected integer")
	}
	return int(value), nil
}

func parseTOMLFloat(raw string) (float64, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(raw), "_", "")
	value, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		return 0, fmt.Errorf("expected number")
	}
	return value, nil
}

package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	InboundTag       = "whitedns-in"
	TunInboundTag    = "whitedns-tun-in"
	OutboundTag      = "stormdns-out"
	V2RayOutboundTag = "v2ray-out"
	DirectTag        = "direct"
	BlockTag         = "block"
)

func Enabled(settings model.SettingsProfile) bool {
	return profiles.NormalizeSettingsProfile(settings).SingBoxEnabled
}

func MasterDNSSettings(settings model.SettingsProfile) model.SettingsProfile {
	settings = profiles.NormalizeSettingsProfile(settings)
	settings.ListenIP = settings.StormDNSListenIP
	settings.ListenPort = settings.StormDNSListenPort
	return settings
}

func PublicListen(settings model.SettingsProfile) (string, int) {
	settings = profiles.NormalizeSettingsProfile(settings)
	return settings.ListenIP, settings.ListenPort
}

func PublicProtocol(inboundType string) string {
	switch strings.ToLower(strings.TrimSpace(inboundType)) {
	case "http":
		return "http"
	case "mixed":
		return "mixed"
	default:
		return "socks"
	}
}

func RenderConfig(settings model.SettingsProfile) (string, error) {
	settings = profiles.NormalizeSettingsProfile(settings)
	if settings.ListenPort == settings.StormDNSListenPort && settings.ListenIP == settings.StormDNSListenIP {
		return "", fmt.Errorf("Xray proxy and MasterDNS/StormDNS upstream cannot use the same listen address")
	}

	inbound := renderLocalInbound(settings.SingBoxInboundType, settings.ListenIP, settings.ListenPort, settings.SOCKS5Authentication, settings.SOCKSUsername, settings.SOCKSPassword)
	outbound := map[string]any{
		"protocol": "socks",
		"tag":      OutboundTag,
		"settings": map[string]any{
			"address": settings.StormDNSListenIP,
			"port":    settings.StormDNSListenPort,
		},
	}
	if settings.SOCKS5Authentication {
		settingsMap := outbound["settings"].(map[string]any)
		settingsMap["user"] = settings.SOCKSUsername
		settingsMap["pass"] = settings.SOCKSPassword
	}

	config := map[string]any{
		"log": map[string]any{
			"loglevel": xrayLogLevel(settings.LogLevel),
		},
		"inbounds": []any{inbound},
		"outbounds": []any{
			outbound,
			map[string]any{"protocol": "freedom", "tag": DirectTag},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules":          []any{},
		},
	}

	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func V2RayPublicListen(settings model.V2RaySettingsProfile) (string, int) {
	settings = profiles.NormalizeV2RaySettingsProfile(settings)
	return settings.ListenIP, settings.ListenPort
}

func V2RayPublicProtocol(settings model.V2RaySettingsProfile) string {
	settings = profiles.NormalizeV2RaySettingsProfile(settings)
	return PublicProtocol(settings.InboundType)
}

func RenderV2RayConfig(profile model.V2RayProfile, settings model.V2RaySettingsProfile) (string, error) {
	profile = profiles.NormalizeV2RayProfile(profile)
	settings = profiles.NormalizeV2RaySettingsProfile(settings)
	if strings.TrimSpace(profile.Server) == "" {
		return "", fmt.Errorf("V2Ray server is required")
	}
	if profile.ServerPort <= 0 || profile.ServerPort > 65535 {
		return "", fmt.Errorf("V2Ray server port is required")
	}
	if settings.ListenPort <= 0 || settings.ListenPort > 65535 {
		return "", fmt.Errorf("V2Ray local proxy port is required")
	}

	inbound := renderLocalInbound(settings.InboundType, settings.ListenIP, settings.ListenPort, false, "", "")
	inbounds := []any{inbound}
	if settings.TunEnabled {
		inbounds = append(inbounds, renderTunInbound(settings))
	}
	outbound, err := renderV2RayOutbound(profile)
	if err != nil {
		return "", err
	}

	outbounds := []any{
		outbound,
		map[string]any{"protocol": "freedom", "tag": DirectTag},
	}
	if settings.IranRoutingEnabled {
		outbounds = append(outbounds, map[string]any{"protocol": "blackhole", "tag": BlockTag})
	}

	config := map[string]any{
		"log": map[string]any{
			"loglevel": xrayLogLevel(settings.LogLevel),
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   renderV2RayRouting(settings),
	}

	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func V2RayTransportServerName(profile model.V2RayProfile) string {
	return v2rayTransportServerName(profiles.NormalizeV2RayProfile(profile))
}

func renderLocalInbound(inboundType string, listenIP string, listenPort int, authEnabled bool, username string, password string) map[string]any {
	protocol := PublicProtocol(inboundType)
	inbound := map[string]any{
		"listen":   listenIP,
		"port":     listenPort,
		"protocol": protocol,
		"tag":      InboundTag,
	}
	settings := map[string]any{}
	switch protocol {
	case "http":
		if authEnabled {
			settings["users"] = []any{map[string]any{"user": username, "pass": password}}
		}
	default:
		settings["auth"] = "noauth"
		settings["udp"] = true
		settings["ip"] = listenIP
		if authEnabled {
			settings["auth"] = "password"
			settings["users"] = []any{map[string]any{"user": username, "pass": password}}
		}
	}
	inbound["settings"] = settings
	return inbound
}

func renderTunInbound(settings model.V2RaySettingsProfile) map[string]any {
	tunSettings := map[string]any{
		"name": settings.TunInterfaceName,
		"MTU":  settings.TunMTU,
	}
	return map[string]any{
		"port":     0,
		"protocol": "tun",
		"tag":      TunInboundTag,
		"settings": tunSettings,
	}
}

func renderV2RayRouting(settings model.V2RaySettingsProfile) map[string]any {
	routing := map[string]any{
		"domainStrategy": "AsIs",
		"rules":          []any{},
	}
	if !settings.IranRoutingEnabled {
		if settings.TunEnabled {
			routing["rules"] = []any{renderTunFallbackRoutingRule()}
		}
		return routing
	}
	routing["domainStrategy"] = "IPIfNonMatch"
	rules := []any{
		map[string]any{
			"type":        "field",
			"domain":      []string{"geosite:category-ads-all"},
			"outboundTag": BlockTag,
		},
		map[string]any{
			"type":        "field",
			"ip":          []string{"geoip:private", "geoip:ir"},
			"outboundTag": DirectTag,
		},
		map[string]any{
			"type":        "field",
			"domain":      []string{"geosite:category-ir"},
			"outboundTag": DirectTag,
		},
	}
	if settings.TunEnabled {
		rules = append(rules, renderTunFallbackRoutingRule())
	}
	routing["rules"] = rules
	return routing
}

func renderTunFallbackRoutingRule() map[string]any {
	return map[string]any{
		"type":        "field",
		"inboundTag":  []string{TunInboundTag},
		"outboundTag": V2RayOutboundTag,
	}
}

func renderV2RayOutbound(profile model.V2RayProfile) (map[string]any, error) {
	if usesV2RayStreamSettings(profile) && profile.Reality && strings.TrimSpace(profile.RealityPublicKey) == "" {
		return nil, fmt.Errorf("Reality public key is required")
	}
	if usesV2RayStreamSettings(profile) && profile.Network == "quic" {
		return nil, fmt.Errorf("QUIC transport is not supported by the bundled Xray runtime configuration")
	}
	if profile.Protocol == model.V2RayProtocolWireGuard && strings.TrimSpace(profile.StreamSettings) != "" {
		return nil, fmt.Errorf("WireGuard stream settings are not supported by Xray")
	}

	outbound := map[string]any{
		"protocol": xrayOutboundProtocol(profile.Protocol),
		"tag":      V2RayOutboundTag,
	}
	var settings map[string]any
	switch profile.Protocol {
	case model.V2RayProtocolVLESS:
		if strings.TrimSpace(profile.UUID) == "" {
			return nil, fmt.Errorf("VLESS UUID is required")
		}
		settings = map[string]any{
			"address":    profile.Server,
			"port":       profile.ServerPort,
			"id":         profile.UUID,
			"encryption": "none",
		}
		if profile.Flow != "" {
			settings["flow"] = profile.Flow
		}
		if profile.PacketEncoding != "" {
			settings["packetEncoding"] = profile.PacketEncoding
		}
	case model.V2RayProtocolVMess:
		if strings.TrimSpace(profile.UUID) == "" {
			return nil, fmt.Errorf("VMess UUID is required")
		}
		settings = map[string]any{
			"address":  profile.Server,
			"port":     profile.ServerPort,
			"id":       profile.UUID,
			"alterId":  profile.AlterID,
			"security": firstNonEmpty(profile.Security, "auto"),
		}
	case model.V2RayProtocolTrojan:
		if strings.TrimSpace(profile.Password) == "" {
			return nil, fmt.Errorf("Trojan password is required")
		}
		settings = map[string]any{
			"address":  profile.Server,
			"port":     profile.ServerPort,
			"password": profile.Password,
		}
	case model.V2RayProtocolShadowsocks:
		if strings.TrimSpace(profile.Password) == "" {
			return nil, fmt.Errorf("Shadowsocks password is required")
		}
		if strings.TrimSpace(profile.ShadowsocksMethod) == "" {
			return nil, fmt.Errorf("Shadowsocks method is required")
		}
		settings = map[string]any{
			"address":  profile.Server,
			"port":     profile.ServerPort,
			"method":   profile.ShadowsocksMethod,
			"password": profile.Password,
		}
		if profile.UoT {
			settings["uot"] = true
			if profile.UoTVersion > 0 {
				settings["UoTVersion"] = profile.UoTVersion
			}
		}
	case model.V2RayProtocolHysteria2:
		if strings.TrimSpace(profile.HysteriaAuth) == "" {
			return nil, fmt.Errorf("Hysteria2 auth is required")
		}
		settings = map[string]any{
			"version": 2,
			"address": profile.Server,
			"port":    profile.ServerPort,
		}
	case model.V2RayProtocolWireGuard:
		if strings.TrimSpace(profile.WireGuardSecretKey) == "" {
			return nil, fmt.Errorf("WireGuard secret key is required")
		}
		if strings.TrimSpace(profile.WireGuardPeerPublicKey) == "" {
			return nil, fmt.Errorf("WireGuard peer public key is required")
		}
		endpoint := net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort))
		peer := map[string]any{
			"endpoint":  endpoint,
			"publicKey": profile.WireGuardPeerPublicKey,
		}
		if profile.WireGuardPreSharedKey != "" {
			peer["preSharedKey"] = profile.WireGuardPreSharedKey
		}
		if profile.WireGuardKeepAlive > 0 {
			peer["keepAlive"] = profile.WireGuardKeepAlive
		}
		if allowed := splitList(profile.WireGuardAllowedIPs); len(allowed) > 0 {
			peer["allowedIPs"] = allowed
		}
		settings = map[string]any{
			"secretKey":      profile.WireGuardSecretKey,
			"address":        splitList(profile.WireGuardLocalAddresses),
			"peers":          []any{peer},
			"noKernelTun":    profile.WireGuardNoKernelTun,
			"domainStrategy": firstNonEmpty(profile.WireGuardDomainStrategy, "ForceIP"),
		}
		if profile.WireGuardMTU > 0 {
			settings["mtu"] = profile.WireGuardMTU
		}
		if reserved := parseIntList(profile.WireGuardReserved); len(reserved) > 0 {
			settings["reserved"] = reserved
		}
	case model.V2RayProtocolSOCKS:
		settings = map[string]any{
			"address": profile.Server,
			"port":    profile.ServerPort,
		}
		if profile.Username != "" {
			settings["user"] = profile.Username
		}
		if profile.Password != "" {
			settings["pass"] = profile.Password
		}
	case model.V2RayProtocolHTTP:
		settings = map[string]any{
			"address": profile.Server,
			"port":    profile.ServerPort,
		}
		if profile.Username != "" {
			settings["user"] = profile.Username
		}
		if profile.Password != "" {
			settings["pass"] = profile.Password
		}
		if profile.HTTPHeaders != "" {
			headers, err := parseJSONObject(profile.HTTPHeaders, "HTTP headers")
			if err != nil {
				return nil, err
			}
			settings["headers"] = headers
		}
	default:
		return nil, fmt.Errorf("unsupported V2Ray protocol")
	}
	if overrides, err := parseJSONObject(profile.OutboundSettings, "outbound settings"); err != nil {
		return nil, err
	} else if len(overrides) > 0 {
		mergeMap(settings, overrides)
	}
	outbound["settings"] = settings
	if usesV2RayStreamSettings(profile) {
		stream, err := renderV2RayStreamSettings(profile)
		if err != nil {
			return nil, err
		}
		if len(stream) > 0 {
			outbound["streamSettings"] = stream
		}
	}
	return outbound, nil
}

func renderV2RayStreamSettings(profile model.V2RayProfile) (map[string]any, error) {
	stream := map[string]any{
		"network":  xrayNetwork(profile.Network),
		"security": "none",
	}
	if profile.Protocol == model.V2RayProtocolHysteria2 {
		settings := map[string]any{
			"version": 2,
			"auth":    profile.HysteriaAuth,
		}
		if profile.HysteriaUDPIdleTimeout > 0 {
			settings["udpIdleTimeout"] = profile.HysteriaUDPIdleTimeout
		}
		if profile.HysteriaMasquerade != "" {
			masquerade, err := parseJSONObject(profile.HysteriaMasquerade, "Hysteria masquerade")
			if err != nil {
				return nil, err
			}
			settings["masquerade"] = masquerade
		}
		stream["network"] = "hysteria"
		stream["hysteriaSettings"] = settings
		if profile.TLS || profile.SNI != "" || profile.ALPN != "" || profile.AllowInsecure {
			stream["security"] = "tls"
			stream["tlsSettings"] = renderTLSSettings(profile)
		}
	} else if profile.Reality {
		stream["security"] = "reality"
		stream["realitySettings"] = renderRealitySettings(profile)
	} else if profile.TLS {
		stream["security"] = "tls"
		stream["tlsSettings"] = renderTLSSettings(profile)
	}
	switch profile.Network {
	case "ws":
		settings := map[string]any{}
		if profile.TransportPath != "" {
			settings["path"] = profile.TransportPath
		}
		if profile.TransportHost != "" {
			settings["host"] = profile.TransportHost
		}
		if profile.WebSocketEarlyData > 0 {
			settings["path"] = appendEarlyDataToPath(firstNonEmpty(profile.TransportPath, "/"), profile.WebSocketEarlyData)
		}
		stream["wsSettings"] = settings
	case "grpc":
		settings := map[string]any{}
		if profile.ServiceName != "" {
			settings["serviceName"] = profile.ServiceName
		}
		if profile.TransportHost != "" {
			settings["authority"] = profile.TransportHost
		}
		stream["grpcSettings"] = settings
	case "kcp":
		stream["kcpSettings"] = map[string]any{}
	case "httpupgrade":
		settings := map[string]any{}
		if profile.TransportPath != "" {
			settings["path"] = profile.TransportPath
		}
		if profile.TransportHost != "" {
			settings["host"] = profile.TransportHost
		}
		stream["httpupgradeSettings"] = settings
	case "xhttp", "http":
		settings := map[string]any{}
		if profile.TransportPath != "" {
			settings["path"] = profile.TransportPath
		}
		if profile.TransportHost != "" {
			settings["host"] = profile.TransportHost
		}
		mode := strings.TrimSpace(profile.XHTTPMode)
		if profile.Network == "http" && mode == "" {
			mode = "stream-one"
		}
		if mode != "" {
			settings["mode"] = mode
		}
		if extra := strings.TrimSpace(profile.XHTTPExtra); extra != "" {
			var parsed any
			if err := json.Unmarshal([]byte(extra), &parsed); err == nil {
				settings["extra"] = parsed
			} else {
				settings["extra"] = extra
			}
		}
		stream["xhttpSettings"] = settings
	}
	if overrides, err := parseJSONObject(profile.StreamSettings, "stream settings"); err != nil {
		return nil, err
	} else if len(overrides) > 0 {
		mergeMap(stream, overrides)
	}
	return stream, nil
}

func usesV2RayStreamSettings(profile model.V2RayProfile) bool {
	switch profile.Protocol {
	case model.V2RayProtocolVLESS, model.V2RayProtocolVMess, model.V2RayProtocolTrojan, model.V2RayProtocolHysteria2:
		return true
	case model.V2RayProtocolHTTP:
		return profile.TLS || strings.TrimSpace(profile.StreamSettings) != ""
	case model.V2RayProtocolShadowsocks, model.V2RayProtocolSOCKS:
		return strings.TrimSpace(profile.StreamSettings) != ""
	default:
		return false
	}
}

func xrayOutboundProtocol(protocol string) string {
	if protocol == model.V2RayProtocolHysteria2 {
		return "hysteria"
	}
	return protocol
}

func xrayNetwork(network string) string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "ws", "websocket":
		return "websocket"
	case "kcp", "mkcp":
		return "mkcp"
	case "grpc":
		return "grpc"
	case "httpupgrade":
		return "httpupgrade"
	case "xhttp", "splithttp", "http", "h2":
		return "xhttp"
	default:
		return "raw"
	}
}

func renderTLSSettings(profile model.V2RayProfile) map[string]any {
	tls := map[string]any{}
	serverName := v2rayTransportServerName(profile)
	if serverName != "" {
		tls["serverName"] = serverName
	}
	if profile.AllowInsecure {
		tls["allowInsecure"] = true
	}
	if alpn := splitList(profile.ALPN); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if profile.UTLSFingerprint != "" {
		tls["fingerprint"] = profile.UTLSFingerprint
	}
	if profile.ECHConfigList != "" {
		tls["echConfigList"] = profile.ECHConfigList
	}
	return tls
}

func renderRealitySettings(profile model.V2RayProfile) map[string]any {
	reality := map[string]any{}
	serverName := v2rayTransportServerName(profile)
	if serverName != "" {
		reality["serverName"] = serverName
	}
	if profile.UTLSFingerprint != "" {
		reality["fingerprint"] = profile.UTLSFingerprint
	}
	if profile.RealityPublicKey != "" {
		reality["password"] = profile.RealityPublicKey
	}
	if profile.RealityShortID != "" {
		reality["shortId"] = profile.RealityShortID
	}
	return reality
}

func v2rayTransportServerName(profile model.V2RayProfile) string {
	if serverName := cleanServerName(profile.SNI); serverName != "" {
		return serverName
	}
	if isHTTPBasedTransport(profile.Network) {
		if serverName := cleanServerName(firstHeaderHost(profile.TransportHost)); serverName != "" {
			return serverName
		}
	}
	if serverName := cleanServerName(profile.Server); serverName != "" {
		return serverName
	}
	return ""
}

func isHTTPBasedTransport(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "ws", "websocket", "grpc", "httpupgrade", "xhttp", "splithttp", "http", "h2":
		return true
	default:
		return false
	}
}

func firstHeaderHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if before, _, ok := strings.Cut(value, ","); ok {
		return strings.TrimSpace(before)
	}
	return value
}

func cleanServerName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || net.ParseIP(value) != nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	if net.ParseIP(value) != nil {
		return ""
	}
	return value
}

func appendEarlyDataToPath(path string, threshold int) string {
	if threshold <= 0 {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%sed=%d", path, separator, threshold)
}

func parseJSONObject(raw string, label string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, fmt.Errorf("invalid %s JSON: %w", label, err)
	}
	return value, nil
}

func mergeMap(dst map[string]any, src map[string]any) {
	for key, value := range src {
		dst[key] = value
	}
}

func parseIntList(value string) []int {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	out := make([]int, 0, len(fields))
	for _, field := range fields {
		number, err := strconv.Atoi(strings.TrimSpace(field))
		if err == nil {
			out = append(out, number)
		}
	}
	return out
}

func xrayLogLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return "debug"
	case "INFO":
		return "info"
	case "ERROR":
		return "error"
	default:
		return "warning"
	}
}

func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

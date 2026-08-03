package profiles

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/model"
)

var v2rayProfileURLPattern = regexp.MustCompile(`(?i)\b(vless|vmess|trojan|ss|shadowsocks|hy2|hysteria2|hysteria|socks|socks5|http-proxy|https-proxy|http|https)://\S+`)

func ParseV2RayProfileImports(rawText string) ([]model.V2RayProfile, error) {
	profiles := parseWireGuardProfiles(rawText)
	matches := v2rayProfileURLPattern.FindAllString(rawText, -1)
	if len(matches) == 0 && len(profiles) == 0 {
		return nil, fmt.Errorf("no V2Ray profiles found")
	}

	parseErrors := make([]string, 0)
	for idx, rawLink := range matches {
		profile, err := parseV2RayProfile(rawLink)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("profile %d: %v", idx+1, err))
			continue
		}
		profiles = append(profiles, profile)
	}
	if len(profiles) == 0 {
		if len(parseErrors) > 0 {
			return nil, fmt.Errorf("no valid V2Ray profiles found: %s", strings.Join(parseErrors, "; "))
		}
		return nil, fmt.Errorf("no valid V2Ray profiles found")
	}
	return profiles, nil
}

func parseV2RayProfile(rawLink string) (model.V2RayProfile, error) {
	link := normalizeV2RayShareLink(rawLink)
	u, err := url.Parse(link)
	if err != nil {
		return model.V2RayProfile{}, fmt.Errorf("invalid V2Ray link")
	}
	switch strings.ToLower(u.Scheme) {
	case model.V2RayProtocolVLESS:
		return parseVLESSProfile(u)
	case model.V2RayProtocolTrojan:
		return parseTrojanProfile(u)
	case model.V2RayProtocolVMess:
		return parseVMessProfile(link)
	case "ss", model.V2RayProtocolShadowsocks:
		return parseShadowsocksProfile(link)
	case "hy2", "hysteria", model.V2RayProtocolHysteria2:
		return parseHysteriaProfile(u)
	case "socks", "socks5":
		return parseSOCKSProfile(u)
	case "http-proxy", "https-proxy", model.V2RayProtocolHTTP, "https":
		return parseHTTPProxyProfile(u)
	default:
		return model.V2RayProfile{}, fmt.Errorf("unsupported V2Ray protocol")
	}
}

func parseShadowsocksProfile(rawLink string) (model.V2RayProfile, error) {
	link := normalizeV2RayShareLink(rawLink)
	u, err := url.Parse(link)
	if err != nil {
		return model.V2RayProfile{}, fmt.Errorf("invalid Shadowsocks link")
	}
	profile := baseV2RayURLProfile(u, model.V2RayProtocolShadowsocks)
	method := ""
	password := ""
	if u.Hostname() == "" || (u.User == nil && u.Port() == "") {
		payload := strings.TrimPrefix(link, u.Scheme+"://")
		if before, _, ok := strings.Cut(payload, "#"); ok {
			payload = before
		}
		if before, _, ok := strings.Cut(payload, "?"); ok {
			payload = before
		}
		if u.Hostname() != "" {
			payload = u.Host
		}
		raw, err := decodeV2RayBase64(payload)
		if err != nil {
			return model.V2RayProfile{}, fmt.Errorf("invalid Shadowsocks payload")
		}
		method, password, profile.Server, profile.ServerPort = parseUserHostPort(string(raw))
	} else if u.User != nil {
		method = strings.TrimSpace(u.User.Username())
		password, _ = u.User.Password()
		if raw, err := decodeV2RayBase64(method); err == nil {
			decodedMethod, decodedPassword, _, _ := parseUserHostPort(string(raw))
			if decodedMethod == "" {
				decodedMethod, decodedPassword, _ = strings.Cut(string(raw), ":")
			}
			if decodedMethod != "" {
				method = strings.TrimSpace(decodedMethod)
				password = strings.TrimSpace(decodedPassword)
			}
		}
	}
	q := canonicalV2RayQuery(u.Query())
	if value := firstQuery(q, "method", "encryption"); value != "" {
		method = value
	}
	if value := firstQuery(q, "password", "pass"); value != "" {
		password = value
	}
	profile.ShadowsocksMethod = method
	profile.Password = password
	profile.UoT = truthy(firstQuery(q, "uot", "udpOverTcp"))
	profile.UoTVersion = firstQueryInt(q, "uotVersion", "UoTVersion")
	if profile.ShadowsocksMethod == "" {
		return model.V2RayProfile{}, fmt.Errorf("Shadowsocks method is required")
	}
	if profile.Password == "" {
		return model.V2RayProfile{}, fmt.Errorf("Shadowsocks password is required")
	}
	return NormalizeV2RayProfile(profile), nil
}

func parseHysteriaProfile(u *url.URL) (model.V2RayProfile, error) {
	profile := baseV2RayURLProfile(u, model.V2RayProtocolHysteria2)
	q := canonicalV2RayQuery(u.Query())
	profile.HysteriaAuth = strings.TrimSpace(u.User.Username())
	if value := firstQuery(q, "auth", "password"); value != "" {
		profile.HysteriaAuth = value
	}
	profile.HysteriaUDPIdleTimeout = firstQueryInt(q, "udpIdleTimeout", "udp_idle_timeout")
	profile.HysteriaMasquerade = firstQuery(q, "masquerade")
	profile.SNI = firstQuery(q, "sni", "peer", "serverName", "servername")
	profile.ALPN = firstQuery(q, "alpn")
	profile.AllowInsecure = truthy(firstQuery(q, "insecure", "allowInsecure", "allow_insecure"))
	if profile.HysteriaAuth == "" {
		return model.V2RayProfile{}, fmt.Errorf("Hysteria2 auth is required")
	}
	return NormalizeV2RayProfile(profile), nil
}

func parseSOCKSProfile(u *url.URL) (model.V2RayProfile, error) {
	profile := baseV2RayURLProfile(u, model.V2RayProtocolSOCKS)
	if u.User != nil {
		profile.Username = strings.TrimSpace(u.User.Username())
		profile.Password, _ = u.User.Password()
	}
	return NormalizeV2RayProfile(profile), nil
}

func parseHTTPProxyProfile(u *url.URL) (model.V2RayProfile, error) {
	q := canonicalV2RayQuery(u.Query())
	if u.Scheme == "http" || u.Scheme == "https" {
		if !truthy(firstQuery(q, "proxy", "whitedns_proxy")) && !strings.Contains(strings.ToLower(firstQuery(q, "protocol", "type")), "proxy") {
			return model.V2RayProfile{}, fmt.Errorf("HTTP URL is not marked as a proxy profile")
		}
	}
	profile := baseV2RayURLProfile(u, model.V2RayProtocolHTTP)
	if u.Scheme == "https" || u.Scheme == "https-proxy" {
		profile.TLS = true
	}
	if u.User != nil {
		profile.Username = strings.TrimSpace(u.User.Username())
		profile.Password, _ = u.User.Password()
	}
	profile.HTTPHeaders = firstQuery(q, "headers")
	profile.SNI = firstQuery(q, "sni", "serverName", "servername")
	profile.AllowInsecure = truthy(firstQuery(q, "insecure", "allowInsecure", "allow_insecure"))
	return NormalizeV2RayProfile(profile), nil
}

func parseVLESSProfile(u *url.URL) (model.V2RayProfile, error) {
	profile := baseV2RayURLProfile(u, model.V2RayProtocolVLESS)
	profile.UUID = strings.TrimSpace(u.User.Username())
	if profile.UUID == "" {
		return model.V2RayProfile{}, fmt.Errorf("VLESS UUID is required")
	}
	q := canonicalV2RayQuery(u.Query())
	profile.Flow = firstQuery(q, "flow")
	applyV2RayQuery(&profile, q)
	return NormalizeV2RayProfile(profile), nil
}

func parseTrojanProfile(u *url.URL) (model.V2RayProfile, error) {
	profile := baseV2RayURLProfile(u, model.V2RayProtocolTrojan)
	profile.Password = strings.TrimSpace(u.User.Username())
	if profile.Password == "" {
		return model.V2RayProfile{}, fmt.Errorf("Trojan password is required")
	}
	profile.TLS = true
	applyV2RayQuery(&profile, canonicalV2RayQuery(u.Query()))
	return NormalizeV2RayProfile(profile), nil
}

func baseV2RayURLProfile(u *url.URL, protocol string) model.V2RayProfile {
	port, _ := strconv.Atoi(strings.TrimSpace(u.Port()))
	name, _ := url.QueryUnescape(strings.TrimSpace(u.Fragment))
	if name == "" {
		name = strings.ToUpper(protocol) + " Connection"
	}
	return model.V2RayProfile{
		Name:       name,
		Protocol:   protocol,
		Server:     strings.TrimSpace(u.Hostname()),
		ServerPort: port,
		Network:    "tcp",
	}
}

func parseUserHostPort(value string) (string, string, string, int) {
	userInfo, hostPort, ok := strings.Cut(strings.TrimSpace(value), "@")
	if !ok {
		return "", "", "", 0
	}
	method, password, _ := strings.Cut(userInfo, ":")
	host := strings.TrimSpace(hostPort)
	port := 0
	if splitHost, splitPort, err := net.SplitHostPort(hostPort); err == nil {
		host = strings.Trim(splitHost, "[]")
		port, _ = strconv.Atoi(splitPort)
	} else if idx := strings.LastIndex(hostPort, ":"); idx > -1 {
		host = strings.Trim(hostPort[:idx], "[]")
		port, _ = strconv.Atoi(hostPort[idx+1:])
	}
	return strings.TrimSpace(method), strings.TrimSpace(password), strings.TrimSpace(host), port
}

func parseWireGuardProfiles(rawText string) []model.V2RayProfile {
	if !strings.Contains(rawText, "[Interface]") || !strings.Contains(rawText, "[Peer]") {
		return nil
	}
	section := ""
	values := map[string]map[string]string{"interface": {}, "peer": {}}
	for _, line := range strings.Split(strings.ReplaceAll(strings.ReplaceAll(rawText, "\r\n", "\n"), "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		switch strings.ToLower(line) {
		case "[interface]":
			section = "interface"
			continue
		case "[peer]":
			section = "peer"
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		values[section][strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	privateKey := values["interface"]["privatekey"]
	publicKey := values["peer"]["publickey"]
	endpoint := values["peer"]["endpoint"]
	if privateKey == "" || publicKey == "" || endpoint == "" {
		return nil
	}
	host := endpoint
	port := 0
	if splitHost, splitPort, err := net.SplitHostPort(endpoint); err == nil {
		host = strings.Trim(splitHost, "[]")
		port, _ = strconv.Atoi(splitPort)
	} else if idx := strings.LastIndex(endpoint, ":"); idx > -1 {
		host = strings.Trim(endpoint[:idx], "[]")
		port, _ = strconv.Atoi(endpoint[idx+1:])
	}
	profile := model.V2RayProfile{
		Name:                    firstNonEmpty(values["interface"]["name"], values["peer"]["name"], "WireGuard"),
		Protocol:                model.V2RayProtocolWireGuard,
		Server:                  host,
		ServerPort:              port,
		WireGuardSecretKey:      privateKey,
		WireGuardLocalAddresses: values["interface"]["address"],
		WireGuardPeerPublicKey:  publicKey,
		WireGuardPreSharedKey:   values["peer"]["presharedkey"],
		WireGuardAllowedIPs:     values["peer"]["allowedips"],
		WireGuardKeepAlive:      atoi(values["peer"]["persistentkeepalive"]),
		WireGuardMTU:            atoi(values["interface"]["mtu"]),
		WireGuardNoKernelTun:    true,
	}
	return []model.V2RayProfile{NormalizeV2RayProfile(profile)}
}

func applyV2RayQuery(profile *model.V2RayProfile, q url.Values) {
	security := strings.ToLower(firstQuery(q, "security", "tls"))
	tlsValue := firstQuery(q, "tls")
	if security != "" || tlsValue != "" {
		profile.TLS = security == "tls" || security == "reality" || truthy(tlsValue)
	}
	profile.Reality = profile.Reality || security == "reality"
	profile.Network = firstQuery(q, "type", "net", "network")
	profile.PacketEncoding = firstQuery(q, "packetEncoding", "packet_encoding")
	profile.SNI = firstQuery(q, "sni", "peer", "serverName", "servername")
	profile.ALPN = firstQuery(q, "alpn")
	profile.AllowInsecure = truthy(firstQuery(q, "allowInsecure", "allowinsecure", "allow_insecure", "insecure"))
	profile.UTLSFingerprint = firstQuery(q, "fp", "fingerprint", "utlsFingerprint", "utls")
	profile.ECHConfigList = firstQuery(q, "ech", "echConfigList", "echconfiglist", "ech_config_list")
	profile.RealityPublicKey = firstQuery(q, "pbk", "publicKey")
	profile.RealityShortID = firstQuery(q, "sid", "shortId")
	profile.TransportPath = firstQuery(q, "path")
	profile.TransportHost = firstQuery(q, "host")
	profile.ServiceName = firstQuery(q, "serviceName", "service")
	profile.XHTTPMode = firstQuery(q, "mode", "xhttpMode", "xhttp_mode")
	profile.XHTTPExtra = firstQuery(q, "extra", "xhttpExtra", "xhttp_extra")
	profile.WebSocketEarlyData = firstQueryInt(q, "ed", "maxEarlyData", "max_early_data")
	profile.WebSocketEarlyDataHeader = firstQuery(q, "eh", "earlyDataHeaderName", "early_data_header_name")
}

type vmessShare struct {
	PS             string          `json:"ps"`
	Add            string          `json:"add"`
	Port           json.RawMessage `json:"port"`
	ID             string          `json:"id"`
	AID            json.RawMessage `json:"aid"`
	Scy            string          `json:"scy"`
	Net            string          `json:"net"`
	Type           string          `json:"type"`
	Host           string          `json:"host"`
	Path           string          `json:"path"`
	TLS            string          `json:"tls"`
	SNI            string          `json:"sni"`
	ALPN           string          `json:"alpn"`
	FP             string          `json:"fp"`
	ECH            string          `json:"ech"`
	ECHConfigList  string          `json:"echConfigList"`
	AllowInsecure  json.RawMessage `json:"allowInsecure"`
	PacketEncoding string          `json:"packetEncoding"`
	Mode           string          `json:"mode"`
	Extra          json.RawMessage `json:"extra"`
}

func parseVMessProfile(rawLink string) (model.V2RayProfile, error) {
	separator := strings.Index(rawLink, "://")
	if separator == -1 {
		return model.V2RayProfile{}, fmt.Errorf("invalid VMess link")
	}
	encoded := strings.TrimSpace(rawLink[separator+3:])
	raw, err := decodeV2RayBase64(encoded)
	if err != nil {
		return model.V2RayProfile{}, fmt.Errorf("invalid VMess payload")
	}
	var payload vmessShare
	if err := json.Unmarshal(raw, &payload); err != nil {
		return model.V2RayProfile{}, fmt.Errorf("invalid VMess JSON")
	}
	name := strings.TrimSpace(payload.PS)
	if name == "" {
		name = "VMess Connection"
	}
	profile := model.V2RayProfile{
		Name:            name,
		Protocol:        model.V2RayProtocolVMess,
		Server:          strings.TrimSpace(payload.Add),
		ServerPort:      rawJSONInt(payload.Port),
		UUID:            strings.TrimSpace(payload.ID),
		AlterID:         rawJSONInt(payload.AID),
		Security:        strings.TrimSpace(payload.Scy),
		Network:         strings.TrimSpace(payload.Net),
		PacketEncoding:  strings.TrimSpace(payload.PacketEncoding),
		TLS:             strings.EqualFold(strings.TrimSpace(payload.TLS), "tls"),
		SNI:             strings.TrimSpace(payload.SNI),
		ALPN:            strings.TrimSpace(payload.ALPN),
		AllowInsecure:   rawJSONBool(payload.AllowInsecure),
		UTLSFingerprint: strings.TrimSpace(payload.FP),
		ECHConfigList:   firstNonEmpty(strings.TrimSpace(payload.ECH), strings.TrimSpace(payload.ECHConfigList)),
		TransportHost:   strings.TrimSpace(payload.Host),
		XHTTPMode:       strings.TrimSpace(payload.Mode),
		XHTTPExtra:      rawJSONText(payload.Extra),
	}
	if strings.EqualFold(strings.TrimSpace(payload.Net), "grpc") {
		profile.ServiceName = strings.TrimSpace(payload.Path)
	} else {
		profile.TransportPath = strings.TrimSpace(payload.Path)
	}
	if profile.UUID == "" {
		return model.V2RayProfile{}, fmt.Errorf("VMess UUID is required")
	}
	return NormalizeV2RayProfile(profile), nil
}

func decodeV2RayBase64(encoded string) ([]byte, error) {
	value := strings.TrimSpace(encoded)
	value = strings.TrimRight(value, "=")
	attempts := []*base64.Encoding{
		base64.RawStdEncoding,
		base64.RawURLEncoding,
		base64.StdEncoding,
		base64.URLEncoding,
	}
	padded := value
	if remainder := len(padded) % 4; remainder != 0 {
		padded += strings.Repeat("=", 4-remainder)
	}
	for _, enc := range attempts {
		input := value
		if enc == base64.StdEncoding || enc == base64.URLEncoding {
			input = padded
		}
		if raw, err := enc.DecodeString(input); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func rawJSONInt(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var number int
	if err := json.Unmarshal(raw, &number); err == nil {
		return number
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		number, _ = strconv.Atoi(strings.TrimSpace(text))
	}
	return number
}

func rawJSONBool(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var flag bool
	if err := json.Unmarshal(raw, &flag); err == nil {
		return flag
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return truthy(text)
	}
	var number int
	if err := json.Unmarshal(raw, &number); err == nil {
		return number != 0
	}
	return false
}

func rawJSONText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(string(raw))
}

func normalizeV2RayShareLink(rawLink string) string {
	link := strings.TrimSpace(rawLink)
	link = strings.ReplaceAll(link, "&amp%3B", "&")
	link = strings.ReplaceAll(link, "&amp%3b", "&")
	return html.UnescapeString(link)
}

func canonicalV2RayQuery(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for key, values := range q {
		canonicalKey := key
		for strings.HasPrefix(strings.ToLower(canonicalKey), "amp;") {
			canonicalKey = canonicalKey[4:]
		}
		canonicalKey = strings.TrimPrefix(canonicalKey, ";")
		canonicalKey = strings.TrimSpace(canonicalKey)
		if canonicalKey == "" {
			continue
		}
		out[canonicalKey] = append(out[canonicalKey], values...)
	}
	return out
}

func firstQuery(q url.Values, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(q.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func firstQueryInt(q url.Values, keys ...string) int {
	value := firstQuery(q, keys...)
	if value == "" {
		return 0
	}
	number, _ := strconv.Atoi(value)
	return number
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func atoi(value string) int {
	number, _ := strconv.Atoi(strings.TrimSpace(value))
	return number
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

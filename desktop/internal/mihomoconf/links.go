// Package mihomoconf turns subscription content into the mihomo configuration
// the engine reads.
//
// This file is the share-link converter, ported from SubConvConverter.kt in
// WhiteDNS/WhiteVPN. Behaviour is matched deliberately for the four link types
// the phone understands — vless, vmess, trojan and ss — so a subscription that
// yields the same nodes there yields them here.
//
// Hysteria2 is the one deliberate addition. The phone skips it; this engine
// supports it, and a desktop has the bandwidth to make it worth having. That is
// a divergence from parity, recorded as one in ANDROID-PARITY.md, rather than a
// gap. Everything else the phone drops — socks, tuic — is still dropped, because
// a desktop quietly connecting through a node the phone never offers is a
// different product.
package mihomoconf

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
)

// errSkipLink marks a link this converter will not represent. It never escapes:
// convert drops the line and moves on, exactly as the phone app does.
var errSkipLink = errors.New("mihomoconf: unsupported or malformed link")

// Proxy is one mihomo proxy definition.
type Proxy map[string]any

// Name returns the proxy's display name.
func (p Proxy) Name() string {
	name, _ := p["name"].(string)
	return name
}

// userAgents are the browsers a WebSocket transport claims to be. Sending the
// same one every time would make the traffic trivially fingerprintable.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
}

// pickUserAgent is a variable so tests can make the output deterministic.
var pickUserAgent = func() string { return userAgents[rand.Intn(len(userAgents))] }

// ConvertLinks parses subscription content into mihomo proxies.
//
// The whole body may be base64, and usually is: the WhiteDNS catalogue arrives
// that way. Individual malformed lines are skipped rather than failing the
// batch, because one bad node in a subscription of hundreds should not cost the
// user the rest.
func ConvertLinks(input string) ([]Proxy, error) {
	proxies, _, err := ConvertLinksWithSources(input)
	return proxies, err
}

// ConvertLinksWithSources is ConvertLinks, and also the line each proxy came
// from. Sharing a node means handing back the link it arrived as, and only the
// converter knows which line survived and which was skipped.
func ConvertLinksWithSources(input string) ([]Proxy, []string, error) {
	body := input
	if decoded, ok := decodeBase64Text(input); ok {
		body = decoded
	}

	names := newNameRegistry()
	var proxies []Proxy
	var sources []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimRight(raw, " \r")
		if !strings.Contains(line, "://") {
			continue
		}
		scheme := strings.ToLower(line[:strings.Index(line, "://")])

		var (
			proxy Proxy
			err   error
		)
		switch scheme {
		case "vless":
			proxy, err = parseVless(line, names)
		case "vmess":
			proxy, err = parseVmess(line, names)
		case "trojan":
			proxy, err = parseTrojan(line, names)
		case "ss":
			proxy, err = parseShadowsocks(line, names)
		case "hysteria2", "hy2":
			proxy, err = parseHysteria2(line, names)
		default:
			continue
		}
		if err != nil {
			continue
		}
		proxies = append(proxies, proxy)
		sources = append(sources, strings.TrimSpace(line))
	}
	if len(proxies) == 0 {
		return nil, nil, errors.New("mihomoconf: no usable proxies in this subscription")
	}
	return proxies, sources, nil
}

// --- vless / vmess-aead ------------------------------------------------------

func parseVless(line string, names *nameRegistry) (Proxy, error) {
	uri, err := splitURI(line)
	if err != nil {
		return nil, err
	}
	query := parseQuery(uri.rawQuery)
	proxy, err := parseVShare(uri, query, names, "vless", true)
	if err != nil {
		return nil, err
	}
	if flow := query["flow"]; strings.TrimSpace(flow) != "" {
		proxy["flow"] = strings.ToLower(flow)
	}
	if encryption := query["encryption"]; strings.TrimSpace(encryption) != "" {
		proxy["encryption"] = encryption
	}
	return proxy, nil
}

// parseVShare covers the URI-with-query family: vless, and vmess in its newer
// AEAD form.
func parseVShare(uri splitURL, query map[string]string, names *nameRegistry, kind string, decodeHost bool) (Proxy, error) {
	endpoint, err := parseEndpoint(uri, decodeHost)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpoint.userInfo) == "" {
		return nil, errSkipLink
	}

	proxy := Proxy{
		"name":   names.register(decodeComponent(uri.rawFragment)),
		"type":   kind,
		"server": endpoint.host,
		"port":   endpoint.port,
		"uuid":   endpoint.userInfo,
		"udp":    true,
	}

	security := strings.ToLower(query["security"])
	if strings.HasSuffix(security, "tls") || security == "reality" {
		proxy["tls"] = true
		proxy["client-fingerprint"] = orDefault(query["fp"], "chrome")
		if alpn := query["alpn"]; strings.TrimSpace(alpn) != "" {
			proxy["alpn"] = strings.Split(alpn, ",")
		}
		if pcs := query["pcs"]; strings.TrimSpace(pcs) != "" {
			proxy["fingerprint"] = pcs
		}
	}
	if sni := query["sni"]; strings.TrimSpace(sni) != "" {
		proxy["servername"] = sni
	}
	if publicKey := query["pbk"]; strings.TrimSpace(publicKey) != "" {
		reality := map[string]any{"public-key": publicKey}
		if shortID := query["sid"]; strings.TrimSpace(shortID) != "" {
			reality["short-id"] = shortID
		}
		proxy["reality-opts"] = reality
	}

	switch query["packetEncoding"] {
	case "packet":
		proxy["packet-addr"] = true
	case "none":
		// Left unset on purpose.
	default:
		proxy["xudp"] = true
	}

	network := strings.ToLower(orDefault(query["type"], "tcp"))
	headerType := strings.ToLower(query["headerType"])
	switch {
	case network == "tcp" && headerType == "http":
		network = "http"
	case network == "http":
		network = "h2"
	}
	proxy["network"] = network

	switch network {
	case "http":
		proxy["http-opts"] = httpOptionsFromQuery(query)
	case "h2":
		proxy["h2-opts"] = h2Options(query)
	case "ws", "httpupgrade":
		opts, err := wsOptions(query, network)
		if err != nil {
			return nil, err
		}
		proxy["ws-opts"] = opts
	case "grpc":
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": query["serviceName"]}
	case "xhttp":
		proxy["xhttp-opts"] = xhttpOptions(query)
	}
	return proxy, nil
}

// --- vmess -------------------------------------------------------------------

func parseVmess(line string, names *nameRegistry) (Proxy, error) {
	body := strings.TrimPrefix(line, "vmess://")
	decoded, ok := decodeBase64Text(body)
	if !ok {
		// Not base64: this is the AEAD form, which is a normal URI.
		return parseVmessAead(line, names)
	}

	var values map[string]any
	if err := json.Unmarshal([]byte(decoded), &values); err != nil {
		return nil, errSkipLink
	}
	server := jsonString(values, "add")
	uuid := jsonString(values, "id")
	port := jsonInt(values, "port", -1)
	if server == "" || uuid == "" || port < 1 || port > 65535 {
		return nil, errSkipLink
	}

	proxy := Proxy{
		"name":             names.register(jsonString(values, "ps")),
		"type":             "vmess",
		"server":           server,
		"port":             port,
		"uuid":             uuid,
		"alterId":          jsonInt(values, "aid", 0),
		"cipher":           orDefault(jsonString(values, "scy"), "auto"),
		"udp":              true,
		"xudp":             true,
		"tls":              false,
		"skip-cert-verify": false,
	}
	if sni := jsonString(values, "sni"); strings.TrimSpace(sni) != "" {
		proxy["servername"] = sni
	}
	if strings.HasSuffix(strings.ToLower(jsonString(values, "tls")), "tls") {
		proxy["tls"] = true
		if alpn := splitCSV(jsonString(values, "alpn")); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
	}

	network := strings.ToLower(jsonString(values, "net"))
	switch {
	case strings.ToLower(jsonString(values, "type")) == "http":
		network = "http"
	case network == "http":
		network = "h2"
	}
	if network != "" {
		proxy["network"] = network
	}
	host := jsonString(values, "host")
	path := jsonString(values, "path")

	switch network {
	case "http":
		proxy["http-opts"] = httpOptions(path, host)
	case "h2":
		opts := map[string]any{}
		if path != "" {
			opts["path"] = path
		}
		headers := map[string]any{}
		if host != "" {
			headers["Host"] = []string{host}
		}
		opts["headers"] = headers
		proxy["h2-opts"] = opts
	case "ws", "httpupgrade":
		proxy["ws-opts"] = vmessWsOptions(path, host, network)
	case "grpc":
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": path}
	}
	return proxy, nil
}

func parseVmessAead(line string, names *nameRegistry) (Proxy, error) {
	uri, err := splitURI(line)
	if err != nil {
		return nil, err
	}
	query := parseQuery(uri.rawQuery)
	// Parsed as vless because the URI shape is identical, then corrected: the
	// phone app does the same, and the shared path is what keeps the two forms
	// from drifting apart.
	proxy, err := parseVShare(uri, query, names, "vless", false)
	if err != nil {
		return nil, err
	}
	proxy["type"] = "vmess"
	delete(proxy, "flow")
	delete(proxy, "encryption")
	proxy["alterId"] = 0
	proxy["cipher"] = orDefault(query["encryption"], "auto")
	setDefault(proxy, "udp", true)
	setDefault(proxy, "tls", false)
	setDefault(proxy, "xudp", true)
	setDefault(proxy, "skip-cert-verify", false)
	return proxy, nil
}

// --- trojan ------------------------------------------------------------------

func parseTrojan(line string, names *nameRegistry) (Proxy, error) {
	uri, err := splitURI(line)
	if err != nil {
		return nil, err
	}
	endpoint, err := parseEndpoint(uri, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpoint.userInfo) == "" {
		return nil, errSkipLink
	}
	query := parseQuery(uri.rawQuery)

	proxy := Proxy{
		"name":     names.register(decodeComponent(uri.rawFragment)),
		"type":     "trojan",
		"server":   endpoint.host,
		"port":     endpoint.port,
		"password": endpoint.userInfo,
		"udp":      true,
	}
	if allowInsecure, present := query["allowInsecure"]; present {
		proxy["skip-cert-verify"] = parseBool(allowInsecure)
	}
	if sni := query["sni"]; strings.TrimSpace(sni) != "" {
		proxy["sni"] = sni
	}
	if alpn := query["alpn"]; strings.TrimSpace(alpn) != "" {
		proxy["alpn"] = strings.Split(alpn, ",")
	}
	network := strings.ToLower(query["type"])
	if network != "" {
		proxy["network"] = network
	}
	switch network {
	case "ws":
		opts := map[string]any{"headers": map[string]any{"User-Agent": pickUserAgent()}}
		if path := query["path"]; strings.TrimSpace(path) != "" {
			opts["path"] = path
		}
		proxy["ws-opts"] = opts
	case "grpc":
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": query["serviceName"]}
	}
	proxy["client-fingerprint"] = orDefault(query["fp"], "chrome")
	if pcs := query["pcs"]; strings.TrimSpace(pcs) != "" {
		proxy["fingerprint"] = pcs
	}
	return proxy, nil
}

// --- shadowsocks -------------------------------------------------------------

// parseHysteria2 reads a hysteria2 link.
//
// The password is the whole user-info half, not a user:pass pair: hysteria2 has
// one credential and generators write it either way, so anything before a colon
// is part of it rather than a username to be dropped.
func parseHysteria2(line string, names *nameRegistry) (Proxy, error) {
	uri, err := splitURI(line)
	if err != nil {
		return nil, err
	}
	endpoint, err := parseEndpoint(uri, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpoint.userInfo) == "" {
		return nil, errSkipLink
	}
	query := parseQuery(uri.rawQuery)

	proxy := Proxy{
		"name":     names.register(decodeComponent(uri.rawFragment)),
		"type":     "hysteria2",
		"server":   endpoint.host,
		"port":     endpoint.port,
		"password": endpoint.userInfo,
	}
	// insecure and allowInsecure both appear in the wild.
	if insecure, present := query["insecure"]; present {
		proxy["skip-cert-verify"] = parseBool(insecure)
	} else if insecure, present := query["allowInsecure"]; present {
		proxy["skip-cert-verify"] = parseBool(insecure)
	}
	if sni := strings.TrimSpace(query["sni"]); sni != "" {
		proxy["sni"] = sni
	}
	if alpn := strings.TrimSpace(query["alpn"]); alpn != "" {
		proxy["alpn"] = strings.Split(alpn, ",")
	}
	// Salamander is the only obfuscation hysteria2 defines, and it is useless
	// without its password, so neither is carried without the other.
	if obfs := strings.TrimSpace(query["obfs"]); obfs != "" {
		if password := strings.TrimSpace(query["obfs-password"]); password != "" {
			proxy["obfs"] = obfs
			proxy["obfs-password"] = password
		}
	}
	if ports := strings.TrimSpace(query["mport"]); ports != "" {
		// Port hopping: the server listens across a range.
		proxy["ports"] = ports
	}
	if fingerprint := strings.TrimSpace(query["pinSHA256"]); fingerprint != "" {
		proxy["fingerprint"] = fingerprint
	}
	return proxy, nil
}

func parseShadowsocks(line string, names *nameRegistry) (Proxy, error) {
	content := strings.TrimPrefix(line, "ss://")
	body, fragment := cut(content, "#")
	authority, rawQuery := cut(body, "?")
	query := parseQuery(rawQuery)

	// The credentials half may be base64 either on its own or as part of the
	// whole authority, depending on which generator produced the link.
	if !strings.Contains(authority, "@") {
		decoded, ok := decodeBase64Text(authority)
		if !ok {
			return nil, errSkipLink
		}
		authority = decoded
	}
	at := strings.LastIndex(authority, "@")
	if at < 1 {
		return nil, errSkipLink
	}
	rawCredentials := authority[:at]
	credentials := ""
	if strings.Contains(rawCredentials, ":") {
		credentials = decodeComponent(rawCredentials)
	} else {
		decoded, ok := decodeBase64Text(rawCredentials)
		if !ok {
			return nil, errSkipLink
		}
		credentials = decoded
	}
	separator := strings.Index(credentials, ":")
	if separator < 1 {
		return nil, errSkipLink
	}
	host, port, ok := parseHostPort(authority[at+1:])
	if !ok {
		return nil, errSkipLink
	}

	proxy := Proxy{
		"name":     names.register(decodeComponent(fragment)),
		"type":     "ss",
		"server":   host,
		"port":     port,
		"password": credentials[separator+1:],
		"cipher":   credentials[:separator],
		"udp":      true,
	}
	if plugin, present := query["plugin"]; present {
		applyPlugin(proxy, plugin)
	}
	if query["udp-over-tcp"] == "true" || query["uot"] == "1" {
		proxy["udp-over-tcp"] = true
	}
	return proxy, nil
}

func applyPlugin(proxy Proxy, plugin string) {
	segments := strings.Split(plugin, ";")
	name := ""
	if len(segments) > 0 {
		name = segments[0]
	}
	options := map[string]string{}
	for _, segment := range segments[1:] {
		key, value, found := strings.Cut(segment, "=")
		if found {
			options[key] = value
		}
	}

	output := map[string]any{}
	switch {
	case strings.Contains(name, "obfs"):
		if mode := options["obfs"]; strings.TrimSpace(mode) != "" {
			output["mode"] = mode
		}
		if host := options["obfs-host"]; strings.TrimSpace(host) != "" {
			output["host"] = host
		}
		proxy["plugin"] = "obfs"
	case strings.Contains(name, "v2ray-plugin"):
		for _, key := range []string{"mode", "host", "path"} {
			if value := options[key]; strings.TrimSpace(value) != "" {
				output[key] = value
			}
		}
		if strings.Contains(plugin, "tls") {
			output["tls"] = true
		}
		proxy["plugin"] = "v2ray-plugin"
	default:
		return
	}
	if len(output) > 0 {
		proxy["plugin-opts"] = output
	}
}

// --- transport options -------------------------------------------------------

func httpOptionsFromQuery(query map[string]string) map[string]any {
	opts := httpOptions(orDefault(query["path"], "/"), query["host"])
	if method := query["method"]; strings.TrimSpace(method) != "" {
		opts["method"] = method
	}
	return opts
}

func httpOptions(path, host string) map[string]any {
	headers := map[string]any{}
	if strings.TrimSpace(host) != "" {
		headers["Host"] = []string{host}
	}
	return map[string]any{
		"path":    []string{orDefault(path, "/")},
		"headers": headers,
	}
}

func h2Options(query map[string]string) map[string]any {
	opts := map[string]any{
		"path":    []string{orDefault(query["path"], "/")},
		"headers": map[string]any{},
	}
	if host := query["host"]; strings.TrimSpace(host) != "" {
		opts["host"] = []string{host}
	}
	return opts
}

func wsOptions(query map[string]string, network string) (map[string]any, error) {
	opts := map[string]any{
		"path": query["path"],
		"headers": map[string]any{
			"User-Agent": pickUserAgent(),
			"Host":       query["host"],
		},
	}
	if raw := query["ed"]; strings.TrimSpace(raw) != "" {
		earlyData, err := strconv.Atoi(raw)
		if err != nil {
			return nil, errSkipLink
		}
		if network == "ws" {
			opts["max-early-data"] = earlyData
			opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
		} else {
			opts["v2ray-http-upgrade-fast-open"] = true
		}
	}
	if header := query["eh"]; strings.TrimSpace(header) != "" {
		opts["early-data-header-name"] = header
	}
	return opts, nil
}

// vmessWsOptions differs from wsOptions because in the legacy vmess form the
// early-data setting is smuggled inside the path's own query string rather than
// the link's, and has to be lifted out and removed from the path.
func vmessWsOptions(path, host, network string) map[string]any {
	outputPath := orDefault(path, "/")
	_, rawQuery := cut(outputPath, "?")
	query := parseQuery(rawQuery)

	headers := map[string]any{}
	if strings.TrimSpace(host) != "" {
		headers["Host"] = host
	}
	opts := map[string]any{"path": outputPath, "headers": headers}

	if earlyData, err := strconv.Atoi(query["ed"]); err == nil {
		if network == "ws" {
			opts["max-early-data"] = earlyData
			opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
		} else {
			opts["v2ray-http-upgrade-fast-open"] = true
		}
		outputPath = removeQueryParameter(outputPath, "ed")
		opts["path"] = outputPath
	}
	if header := query["eh"]; strings.TrimSpace(header) != "" {
		opts["early-data-header-name"] = header
	}
	return opts
}

func xhttpOptions(query map[string]string) map[string]any {
	opts := map[string]any{}
	for _, key := range []string{"path", "host", "mode"} {
		if value := query[key]; strings.TrimSpace(value) != "" {
			opts[key] = value
		}
	}
	if raw, present := query["extra"]; present {
		var extra map[string]any
		if json.Unmarshal([]byte(raw), &extra) == nil {
			applyXhttpExtra(opts, extra)
		}
	}
	return opts
}

func applyXhttpExtra(target map[string]any, extra map[string]any) {
	if boolValue(extra["noGRPCHeader"]) {
		target["no-grpc-header"] = true
	}
	stringFields := [][2]string{
		{"xPaddingBytes", "x-padding-bytes"},
		{"xPaddingKey", "x-padding-key"},
		{"xPaddingHeader", "x-padding-header"},
		{"xPaddingPlacement", "x-padding-placement"},
		{"xPaddingMethod", "x-padding-method"},
		{"uplinkHttpMethod", "uplink-http-method"},
		{"sessionPlacement", "session-placement"},
		{"sessionKey", "session-key"},
		{"seqPlacement", "seq-placement"},
		{"seqKey", "seq-key"},
		{"uplinkDataPlacement", "uplink-data-placement"},
		{"uplinkDataKey", "uplink-data-key"},
	}
	for _, field := range stringFields {
		if value := jsonString(extra, field[0]); strings.TrimSpace(value) != "" {
			target[field[1]] = value
		}
	}
	if _, present := extra["xPaddingObfsMode"]; present {
		target["x-padding-obfs-mode"] = boolValue(extra["xPaddingObfsMode"])
	}
	numberFields := [][2]string{
		{"uplinkChunkSize", "uplink-chunk-size"},
		{"scMaxEachPostBytes", "sc-max-each-post-bytes"},
		{"scMinPostsIntervalMs", "sc-min-posts-interval-ms"},
	}
	for _, field := range numberFields {
		if value, ok := extra[field[0]].(float64); ok {
			target[field[1]] = int(value)
		}
	}
	if xmux, ok := extra["xmux"].(map[string]any); ok {
		if settings := reuseSettings(xmux); len(settings) > 0 {
			target["reuse-settings"] = settings
		}
	}
	if settings, ok := extra["downloadSettings"].(map[string]any); ok {
		if download := downloadSettings(settings); len(download) > 0 {
			target["download-settings"] = download
		}
	}
}

func reuseSettings(xmux map[string]any) map[string]any {
	output := map[string]any{}
	fields := [][2]string{
		{"maxConnections", "max-connections"},
		{"maxConcurrency", "max-concurrency"},
		{"cMaxReuseTimes", "c-max-reuse-times"},
		{"hMaxRequestTimes", "h-max-request-times"},
		{"hMaxReusableSecs", "h-max-reusable-secs"},
	}
	for _, field := range fields {
		switch value := xmux[field[0]].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				output[field[1]] = value
			}
		case float64:
			// mihomo wants these as strings even when they arrive as numbers.
			output[field[1]] = strconv.Itoa(int(value))
		}
	}
	if period, ok := xmux["hKeepAlivePeriod"].(float64); ok {
		output["h-keep-alive-period"] = int(period)
	}
	return output
}

func downloadSettings(settings map[string]any) map[string]any {
	output := map[string]any{}
	if address := jsonString(settings, "address"); strings.TrimSpace(address) != "" {
		output["server"] = address
	}
	if port, ok := settings["port"].(float64); ok {
		output["port"] = int(port)
	}
	security := strings.ToLower(jsonString(settings, "security"))
	if security == "tls" || security == "reality" {
		output["tls"] = true
		if tls, ok := settings["tlsSettings"].(map[string]any); ok {
			if serverName := jsonString(tls, "serverName"); strings.TrimSpace(serverName) != "" {
				output["servername"] = serverName
			}
			if fingerprint := jsonString(tls, "fingerprint"); strings.TrimSpace(fingerprint) != "" {
				output["client-fingerprint"] = fingerprint
			}
			if alpn, ok := tls["alpn"].([]any); ok && len(alpn) > 0 {
				output["alpn"] = alpn
			}
			if boolValue(tls["allowInsecure"]) {
				output["skip-cert-verify"] = true
			}
		}
		if security == "reality" {
			if reality, ok := settings["realitySettings"].(map[string]any); ok {
				if key := jsonString(reality, "publicKey"); strings.TrimSpace(key) != "" {
					opts := map[string]any{"public-key": key}
					if shortID := jsonString(reality, "shortId"); strings.TrimSpace(shortID) != "" {
						opts["short-id"] = shortID
					}
					output["reality-opts"] = opts
				}
			}
		}
	}
	if xhttp, ok := settings["xhttpSettings"].(map[string]any); ok {
		for _, key := range []string{"path", "host"} {
			if value := jsonString(xhttp, key); strings.TrimSpace(value) != "" {
				output[key] = value
			}
		}
		if headers, ok := xhttp["headers"].(map[string]any); ok && len(headers) > 0 {
			output["headers"] = headers
		}
		applyXhttpExtra(output, xhttp)
	}
	return output
}

// --- URI handling ------------------------------------------------------------

// splitURL holds the raw, still-encoded pieces of a link. The parts are kept
// undecoded because decoding has to happen per component: a password may
// legitimately contain a character that would otherwise be read as a delimiter.
type splitURL struct {
	rawAuthority string
	rawQuery     string
	rawFragment  string
}

func splitURI(value string) (splitURL, error) {
	rest := value
	if index := strings.Index(rest, "://"); index >= 0 {
		rest = rest[index+3:]
	} else {
		return splitURL{}, errSkipLink
	}

	var fragment string
	if index := strings.Index(rest, "#"); index >= 0 {
		fragment = rest[index+1:]
		rest = rest[:index]
	}
	var query string
	if index := strings.Index(rest, "?"); index >= 0 {
		query = rest[index+1:]
		rest = rest[:index]
	}
	if index := strings.Index(rest, "/"); index >= 0 {
		rest = rest[:index]
	}
	if rest == "" {
		return splitURL{}, errSkipLink
	}
	return splitURL{rawAuthority: rest, rawQuery: query, rawFragment: fragment}, nil
}

type endpoint struct {
	userInfo string
	host     string
	port     int
}

func parseEndpoint(uri splitURL, decodeHost bool) (endpoint, error) {
	authority := uri.rawAuthority
	userInfo := ""
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userInfo = decodeComponent(authority[:at])
		authority = authority[at+1:]
	}
	host, port, ok := parseHostPort(authority)
	if !ok && decodeHost {
		// Some generators base64 the host:port half of a vless link.
		if decoded, decodedOK := decodeBase64Text(authority); decodedOK {
			host, port, ok = parseHostPort(decoded)
		}
	}
	if !ok {
		return endpoint{}, errSkipLink
	}
	return endpoint{userInfo: userInfo, host: host, port: port}, nil
}

func parseHostPort(raw string) (string, int, bool) {
	value := strings.TrimSpace(raw)
	if index := strings.Index(value, "/"); index >= 0 {
		value = value[:index]
	}
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end <= 0 {
			return "", 0, false
		}
		port, err := strconv.Atoi(strings.TrimPrefix(value[end+1:], ":"))
		if err != nil || port < 1 || port > 65535 {
			return "", 0, false
		}
		return value[1:end], port, true
	}
	separator := strings.LastIndex(value, ":")
	if separator < 1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[separator+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return value[:separator], port, true
}

// parseQuery keeps the first occurrence of a repeated key, matching the phone.
func parseQuery(raw string) map[string]string {
	output := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return output
	}
	for _, part := range strings.Split(raw, "&") {
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key := decodeComponent(rawKey)
		if key == "" {
			continue
		}
		if _, seen := output[key]; seen {
			continue
		}
		output[key] = decodeComponent(rawValue)
	}
	return output
}

func removeQueryParameter(path, key string) string {
	base, rawQuery := cut(path, "?")
	remaining := url.Values{}
	for name, value := range parseQuery(rawQuery) {
		if name != key {
			remaining.Set(name, value)
		}
	}
	if len(remaining) == 0 {
		return base
	}
	return base + "?" + remaining.Encode()
}

// --- small helpers -----------------------------------------------------------

func decodeComponent(value string) string {
	// A link that is not strictly encoded should still be usable, so a failure
	// here yields the original text rather than discarding the node.
	if decoded, err := url.QueryUnescape(value); err == nil {
		return decoded
	}
	return value
}

func decodeBase64Text(value string) (string, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, value)
	if compact == "" {
		return "", false
	}
	if padding := (4 - len(compact)%4) % 4; padding > 0 {
		compact += strings.Repeat("=", padding)
	}
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return string(decoded), true
	}
	if decoded, err := base64.URLEncoding.DecodeString(compact); err == nil {
		return string(decoded), true
	}
	return "", false
}

func cut(value, separator string) (string, string) {
	before, after, _ := strings.Cut(value, separator)
	return before, after
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func setDefault(proxy Proxy, key string, value any) {
	if _, present := proxy[key]; !present {
		proxy[key] = value
	}
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseBool(value string) bool {
	switch strings.ToLower(value) {
	case "1", "true":
		return true
	}
	return false
}

func jsonString(values map[string]any, key string) string {
	switch value := values[key].(type) {
	case string:
		return value
	case float64:
		return strconv.Itoa(int(value))
	}
	return ""
}

func jsonInt(values map[string]any, key string, fallback int) int {
	switch value := values[key].(type) {
	case float64:
		return int(value)
	case string:
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return parseBool(typed)
	}
	return false
}

// nameRegistry makes display names unique. A subscription routinely repeats a
// name across nodes, and mihomo keys its proxies by name, so duplicates would
// silently collapse into one.
type nameRegistry struct {
	seen map[string]int
}

func newNameRegistry() *nameRegistry { return &nameRegistry{seen: map[string]int{}} }

func (r *nameRegistry) register(name string) string {
	index, present := r.seen[name]
	if !present {
		r.seen[name] = 0
		return name
	}
	next := index + 1
	r.seen[name] = next
	return fmt.Sprintf("%s-%02d", name, next)
}

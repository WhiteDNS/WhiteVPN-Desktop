package mihomoconf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// sing-box configurations, which several panels serve alongside the Clash one.
//
// The schema is a sibling of mihomo's rather than a stranger to it — the same
// protocols under different spellings. `server_port` for `port`, `tag` for
// `name`, a nested `tls` object instead of flat keys, `transport` instead of
// `network` plus `*-opts`. Translating it is mechanical, and worth doing
// because a user who picks "sing-box" in their panel should not have to know
// that this app would rather have had the Clash one.
//
// Outbounds that are not servers — `selector`, `urltest`, `direct`, `block`,
// `dns` — are the provider's routing, not nodes, and are skipped.

// ParseSingBox reads the outbounds of a sing-box configuration.
func ParseSingBox(body string) ([]Proxy, error) {
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		return nil, fmt.Errorf("mihomoconf: not a sing-box configuration: %w", err)
	}
	if len(document.Outbounds) == 0 {
		return nil, fmt.Errorf("mihomoconf: the sing-box configuration has no outbounds")
	}

	names := newNameRegistry()
	proxies := make([]Proxy, 0, len(document.Outbounds))
	for _, outbound := range document.Outbounds {
		proxy, ok := singBoxProxy(outbound)
		if !ok {
			continue
		}
		proxy["name"] = names.register(proxy.Name())
		proxies = append(proxies, proxy)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("mihomoconf: the sing-box configuration has no usable outbounds")
	}
	return proxies, nil
}

func singBoxProxy(outbound map[string]any) (Proxy, bool) {
	kind := strings.ToLower(jsonString(outbound, "type"))
	server := jsonString(outbound, "server")
	port := jsonInt(outbound, "server_port", 0)
	name := jsonString(outbound, "tag")
	if server == "" || port < 1 || port > 65535 || strings.TrimSpace(name) == "" {
		return nil, false
	}

	proxy := Proxy{"name": name, "server": server, "port": port, "udp": true}
	switch kind {
	case "vless":
		proxy["type"] = "vless"
		proxy["uuid"] = jsonString(outbound, "uuid")
		if flow := jsonString(outbound, "flow"); flow != "" {
			proxy["flow"] = flow
		}
	case "vmess":
		proxy["type"] = "vmess"
		proxy["uuid"] = jsonString(outbound, "uuid")
		proxy["alterId"] = jsonInt(outbound, "alter_id", 0)
		proxy["cipher"] = orDefault(jsonString(outbound, "security"), "auto")
	case "trojan":
		proxy["type"] = "trojan"
		proxy["password"] = jsonString(outbound, "password")
	case "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = jsonString(outbound, "method")
		proxy["password"] = jsonString(outbound, "password")
	case "hysteria2":
		proxy["type"] = "hysteria2"
		proxy["password"] = jsonString(outbound, "password")
	default:
		// selector, urltest, direct, block, dns — routing, not a server.
		return nil, false
	}

	applySingBoxTLS(proxy, outbound)
	applySingBoxTransport(proxy, outbound)
	return proxy, true
}

func applySingBoxTLS(proxy Proxy, outbound map[string]any) {
	tls, ok := outbound["tls"].(map[string]any)
	if !ok || !boolValue(tls["enabled"]) {
		return
	}
	proxy["tls"] = true
	if name := jsonString(tls, "server_name"); name != "" {
		// trojan reads it as sni, everything else as servername. Writing the
		// wrong one is a handshake that fails for no visible reason.
		if proxy["type"] == "trojan" || proxy["type"] == "hysteria2" {
			proxy["sni"] = name
		} else {
			proxy["servername"] = name
		}
	}
	if boolValue(tls["insecure"]) {
		proxy["skip-cert-verify"] = true
	}
	if alpn := jsonStrings(tls, "alpn"); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if utls, ok := tls["utls"].(map[string]any); ok && boolValue(utls["enabled"]) {
		proxy["client-fingerprint"] = orDefault(jsonString(utls, "fingerprint"), "chrome")
	}
	if reality, ok := tls["reality"].(map[string]any); ok && boolValue(reality["enabled"]) {
		options := map[string]any{"public-key": jsonString(reality, "public_key")}
		if shortID := jsonString(reality, "short_id"); shortID != "" {
			options["short-id"] = shortID
		}
		proxy["reality-opts"] = options
	}
}

func applySingBoxTransport(proxy Proxy, outbound map[string]any) {
	transport, ok := outbound["transport"].(map[string]any)
	if !ok {
		proxy["network"] = "tcp"
		return
	}
	switch strings.ToLower(jsonString(transport, "type")) {
	case "ws":
		proxy["network"] = "ws"
		options := map[string]any{"path": jsonString(transport, "path")}
		headers := map[string]any{}
		if host := jsonString(transport, "host"); host != "" {
			headers["Host"] = host
		}
		if raw, ok := transport["headers"].(map[string]any); ok {
			for key, value := range raw {
				headers[key] = value
			}
		}
		if len(headers) > 0 {
			options["headers"] = headers
		}
		// sing-box carries early data as its own fields; mihomo expects the
		// length and the header name under ws-opts.
		if early := jsonInt(transport, "max_early_data", 0); early > 0 {
			options["max-early-data"] = early
		}
		if header := jsonString(transport, "early_data_header_name"); header != "" {
			options["early-data-header-name"] = header
		}
		proxy["ws-opts"] = options
	case "grpc":
		proxy["network"] = "grpc"
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": jsonString(transport, "service_name")}
	case "http":
		proxy["network"] = "http"
		options := map[string]any{}
		if path := jsonString(transport, "path"); path != "" {
			options["path"] = []string{path}
		}
		if host := jsonStrings(transport, "host"); len(host) > 0 {
			options["headers"] = map[string]any{"Host": host}
		}
		proxy["http-opts"] = options
	case "httpupgrade":
		proxy["network"] = "httpupgrade"
		proxy["ws-opts"] = map[string]any{
			"path":    jsonString(transport, "path"),
			"headers": map[string]any{"Host": jsonString(transport, "host")},
		}
	default:
		proxy["network"] = "tcp"
	}
}

// jsonStrings reads a field that may be one string or a list of them, which is
// how sing-box writes alpn and http hosts.
func jsonStrings(values map[string]any, key string) []string {
	switch value := values[key].(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	case []any:
		out := make([]string, 0, len(value))
		for _, entry := range value {
			if text, ok := entry.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

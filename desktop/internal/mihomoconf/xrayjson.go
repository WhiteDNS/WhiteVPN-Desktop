package mihomoconf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Xray and V2Ray JSON, which is what a panel serves for v2rayN, MahsaNG and
// Streisand.
//
// Two shapes arrive under this name. A single configuration is an object with
// `outbounds`; a subscription is an array of whole configurations, each with a
// `remarks` naming it, because those clients treat one config as one server.
// Both are read here, and in the array case the remarks becomes the node name —
// it is the only place the name lives.
//
// The proxy itself hides two levels down: `settings.vnext[0]` for vless and
// vmess, `settings.servers[0]` for trojan and shadowsocks, with the transport
// and TLS in a `streamSettings` beside it.

// ParseXrayJSON reads an Xray configuration, or a list of them.
func ParseXrayJSON(body string) ([]Proxy, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("mihomoconf: the configuration is empty")
	}

	names := newNameRegistry()
	var proxies []Proxy

	if strings.HasPrefix(trimmed, "[") {
		var configs []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &configs); err != nil {
			return nil, fmt.Errorf("mihomoconf: not an Xray configuration list: %w", err)
		}
		for _, config := range configs {
			proxies = appendXrayOutbounds(proxies, config, jsonString(config, "remarks"), names)
		}
	} else {
		var config map[string]any
		if err := json.Unmarshal([]byte(trimmed), &config); err != nil {
			return nil, fmt.Errorf("mihomoconf: not an Xray configuration: %w", err)
		}
		proxies = appendXrayOutbounds(proxies, config, "", names)
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("mihomoconf: the configuration has no usable outbounds")
	}
	return proxies, nil
}

func appendXrayOutbounds(into []Proxy, config map[string]any, remarks string, names *nameRegistry) []Proxy {
	// WARP configurations hold several real outbounds rather than one, so they
	// are read whole before the one-server-per-configuration rule below applies.
	if wireGuard := xrayWireGuardProxies(config, remarks, names); len(wireGuard) > 0 {
		return append(into, wireGuard...)
	}

	outbounds, _ := config["outbounds"].([]any)
	for _, entry := range outbounds {
		outbound, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		proxy, ok := xrayProxy(outbound)
		if !ok {
			continue
		}
		// The remarks names the whole configuration, so it belongs to the one
		// outbound that carries traffic. A tag is the fallback, and the address
		// after that, because a node with no name cannot be chosen or measured.
		name := strings.TrimSpace(remarks)
		if name == "" {
			name = strings.TrimSpace(jsonString(outbound, "tag"))
		}
		if name == "" {
			name = fmt.Sprintf("%v:%v", proxy["server"], proxy["port"])
		}
		proxy["name"] = names.register(name)
		into = append(into, proxy)
		// One server per configuration: the rest are freedom, blackhole and dns,
		// which xrayProxy already refuses, but an array entry that somehow held
		// two would otherwise take the remarks twice.
		break
	}
	return into
}

func xrayProxy(outbound map[string]any) (Proxy, bool) {
	protocol := strings.ToLower(jsonString(outbound, "protocol"))
	settings, _ := outbound["settings"].(map[string]any)
	if settings == nil {
		return nil, false
	}

	proxy := Proxy{"udp": true}
	switch protocol {
	case "vless", "vmess":
		next := firstMap(settings["vnext"])
		if next == nil {
			return nil, false
		}
		user := firstMap(next["users"])
		if user == nil {
			return nil, false
		}
		proxy["type"] = protocol
		proxy["server"] = jsonString(next, "address")
		proxy["port"] = jsonInt(next, "port", 0)
		proxy["uuid"] = jsonString(user, "id")
		if protocol == "vless" {
			if flow := jsonString(user, "flow"); flow != "" {
				proxy["flow"] = flow
			}
		} else {
			proxy["alterId"] = jsonInt(user, "alterId", 0)
			proxy["cipher"] = orDefault(jsonString(user, "security"), "auto")
		}
	case "trojan":
		server := firstMap(settings["servers"])
		if server == nil {
			return nil, false
		}
		proxy["type"] = "trojan"
		proxy["server"] = jsonString(server, "address")
		proxy["port"] = jsonInt(server, "port", 0)
		proxy["password"] = jsonString(server, "password")
	case "shadowsocks":
		server := firstMap(settings["servers"])
		if server == nil {
			return nil, false
		}
		proxy["type"] = "ss"
		proxy["server"] = jsonString(server, "address")
		proxy["port"] = jsonInt(server, "port", 0)
		proxy["cipher"] = jsonString(server, "method")
		proxy["password"] = jsonString(server, "password")
	default:
		// freedom, blackhole, dns, socks, http — not servers this app offers.
		return nil, false
	}

	server, _ := proxy["server"].(string)
	port, _ := proxy["port"].(int)
	if strings.TrimSpace(server) == "" || port < 1 || port > 65535 {
		return nil, false
	}

	applyXrayStreamSettings(proxy, outbound)
	return proxy, true
}

func applyXrayStreamSettings(proxy Proxy, outbound map[string]any) {
	stream, _ := outbound["streamSettings"].(map[string]any)
	if stream == nil {
		proxy["network"] = "tcp"
		return
	}

	switch strings.ToLower(jsonString(stream, "security")) {
	case "tls":
		proxy["tls"] = true
		applyXrayTLS(proxy, stream, "tlsSettings")
	case "reality":
		proxy["tls"] = true
		applyXrayTLS(proxy, stream, "realitySettings")
		if reality, ok := stream["realitySettings"].(map[string]any); ok {
			options := map[string]any{"public-key": jsonString(reality, "publicKey")}
			if shortID := jsonString(reality, "shortId"); shortID != "" {
				options["short-id"] = shortID
			}
			proxy["reality-opts"] = options
		}
	}

	network := strings.ToLower(jsonString(stream, "network"))
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "ws", "websocket":
		proxy["network"] = "ws"
		ws, _ := stream["wsSettings"].(map[string]any)
		options := map[string]any{"path": jsonString(ws, "path")}
		if host := jsonString(ws, "host"); host != "" {
			options["headers"] = map[string]any{"Host": host}
		}
		proxy["ws-opts"] = options
	case "grpc":
		proxy["network"] = "grpc"
		grpc, _ := stream["grpcSettings"].(map[string]any)
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": jsonString(grpc, "serviceName")}
	case "httpupgrade":
		proxy["network"] = "httpupgrade"
		upgrade, _ := stream["httpupgradeSettings"].(map[string]any)
		proxy["ws-opts"] = map[string]any{
			"path":    jsonString(upgrade, "path"),
			"headers": map[string]any{"Host": jsonString(upgrade, "host")},
		}
	case "xhttp", "splithttp":
		proxy["network"] = "xhttp"
		settings, _ := stream["xhttpSettings"].(map[string]any)
		if settings == nil {
			settings, _ = stream["splithttpSettings"].(map[string]any)
		}
		options := map[string]any{}
		for _, key := range []string{"path", "host", "mode"} {
			if value := jsonString(settings, key); value != "" {
				options[key] = value
			}
		}
		if extra, ok := settings["extra"].(map[string]any); ok {
			applyXhttpExtra(options, extra)
		}
		proxy["xhttp-opts"] = options
	case "h2", "http":
		proxy["network"] = "h2"
		h2, _ := stream["httpSettings"].(map[string]any)
		options := map[string]any{}
		if path := jsonString(h2, "path"); path != "" {
			options["path"] = path
		}
		if hosts := jsonStrings(h2, "host"); len(hosts) > 0 {
			options["host"] = hosts
		}
		proxy["h2-opts"] = options
	default:
		proxy["network"] = "tcp"
	}
}

func applyXrayTLS(proxy Proxy, stream map[string]any, key string) {
	settings, _ := stream[key].(map[string]any)
	if settings == nil {
		return
	}
	name := jsonString(settings, "serverName")
	if name != "" {
		if proxy["type"] == "trojan" {
			proxy["sni"] = name
		} else {
			proxy["servername"] = name
		}
	}
	if boolValue(settings["allowInsecure"]) {
		proxy["skip-cert-verify"] = true
	}
	if alpn := jsonStrings(settings, "alpn"); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if fingerprint := jsonString(settings, "fingerprint"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
}

func firstMap(value any) map[string]any {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	first, _ := list[0].(map[string]any)
	return first
}

// WireGuard, which Xray carries differently enough to need its own path.
//
// A normal Xray config holds one server and a handful of freedom/blackhole
// outbounds, so appendXrayOutbounds keeps the first that converts and stops. A
// WARP config breaks that rule: it holds two wireguard outbounds that are both
// real, the second dialing through the first via sockopt.dialerProxy — the
// "WoW" chain that routes one WARP hop through another. Keeping only the first
// would silently drop half of what the user imported, so both survive here and
// the chain is rebuilt as mihomo's dialer-proxy.
func xrayWireGuardProxies(config map[string]any, remarks string, names *nameRegistry) []Proxy {
	outbounds, _ := config["outbounds"].([]any)

	type candidate struct {
		tag    string
		dialer string
		proxy  Proxy
	}
	var found []candidate
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok || strings.ToLower(jsonString(outbound, "protocol")) != "wireguard" {
			continue
		}
		proxy, ok := xrayWireGuardProxy(outbound)
		if !ok {
			continue
		}
		sockopt := firstMapValue(outbound, "streamSettings", "sockopt")
		found = append(found, candidate{
			tag:    strings.TrimSpace(jsonString(outbound, "tag")),
			dialer: strings.TrimSpace(jsonString(sockopt, "dialerProxy")),
			proxy:  proxy,
		})
	}
	if len(found) == 0 {
		return nil
	}

	// The remarks names the configuration, and with two hops in it there are two
	// nodes to tell apart, so the second onward is qualified by its tag.
	base := strings.TrimSpace(remarks)
	byTag := make(map[string]string, len(found))
	for index := range found {
		name := base
		if name == "" {
			name = found[index].tag
		} else if index > 0 {
			qualifier := found[index].tag
			if qualifier == "" {
				qualifier = fmt.Sprintf("%d", index+1)
			}
			name = fmt.Sprintf("%s (%s)", base, qualifier)
		}
		if name == "" {
			name = fmt.Sprintf("%v:%v", found[index].proxy["server"], found[index].proxy["port"])
		}
		name = names.register(name)
		found[index].proxy["name"] = name
		if found[index].tag != "" {
			byTag[found[index].tag] = name
		}
	}

	proxies := make([]Proxy, 0, len(found))
	for _, entry := range found {
		if entry.dialer != "" {
			target, ok := byTag[entry.dialer]
			if !ok {
				// The hop it dials through is missing or unreadable, so this one
				// cannot carry traffic either. Offering it would look like a
				// working node and fail on the first packet.
				continue
			}
			entry.proxy["dialer-proxy"] = target
		}
		proxies = append(proxies, entry.proxy)
	}
	return proxies
}

// xrayWireGuardProxy converts one wireguard outbound, without naming it.
func xrayWireGuardProxy(outbound map[string]any) (Proxy, bool) {
	settings, _ := outbound["settings"].(map[string]any)
	if settings == nil {
		return nil, false
	}
	// One peer is what every WARP feed in the wild emits. Mihomo has a full
	// multi-peer `peers` syntax, but guessing at a mapping for a shape nobody
	// has sent us would be inventing behaviour rather than supporting it.
	peers, _ := settings["peers"].([]any)
	if len(peers) != 1 {
		return nil, false
	}
	peer := firstMap(settings["peers"])
	if peer == nil {
		return nil, false
	}

	privateKey := strings.TrimSpace(jsonString(settings, "secretKey"))
	publicKey := strings.TrimSpace(jsonString(peer, "publicKey"))
	if privateKey == "" || publicKey == "" {
		return nil, false
	}
	host, port, ok := splitWireGuardEndpoint(jsonString(peer, "endpoint"))
	if !ok {
		return nil, false
	}

	proxy := Proxy{
		"type":        "wireguard",
		"server":      host,
		"port":        port,
		"private-key": privateKey,
		"public-key":  publicKey,
		"udp":         true,
	}

	// The tunnel's own addresses arrive as CIDRs and split by family, the same
	// way parseWireGuard splits them for links.
	for _, address := range jsonStrings(settings, "address") {
		value := strings.TrimSpace(strings.SplitN(address, "/", 2)[0])
		if value == "" {
			continue
		}
		key := "ip"
		if strings.Contains(value, ":") {
			key = "ipv6"
		}
		if _, taken := proxy[key]; !taken {
			proxy[key] = value
		}
	}
	if _, ok := proxy["ip"]; !ok {
		// Without a v4 address inside the tunnel there is nothing to source from.
		return nil, false
	}

	if allowed := jsonStrings(peer, "allowedIPs"); len(allowed) > 0 {
		proxy["allowed-ips"] = allowed
	}
	if presharedKey := strings.TrimSpace(jsonString(peer, "preSharedKey")); presharedKey != "" {
		proxy["pre-shared-key"] = presharedKey
	}
	if keepalive := jsonInt(peer, "keepAlive", 0); keepalive > 0 {
		proxy["persistent-keepalive"] = keepalive
	}
	if mtu := jsonInt(settings, "mtu", 0); mtu > 0 {
		proxy["mtu"] = mtu
	}
	if reserved, ok := xrayWireGuardReserved(settings["reserved"]); ok {
		proxy["reserved"] = reserved
	}
	return proxy, true
}

// xrayWireGuardReserved reads the three WARP reserved bytes.
//
// Three or none: a partial or out-of-range set is a config we do not understand,
// and passing it through would put the tunnel on the wrong session.
func xrayWireGuardReserved(value any) ([]int, bool) {
	entries, _ := value.([]any)
	if len(entries) != 3 {
		return nil, false
	}
	values := make([]int, 0, 3)
	for _, entry := range entries {
		number, ok := entry.(float64)
		if !ok || number != float64(int(number)) || number < 0 || number > 255 {
			return nil, false
		}
		values = append(values, int(number))
	}
	return values, true
}

// splitWireGuardEndpoint splits "host:port", including the [v6]:port form.
func splitWireGuardEndpoint(value string) (string, int, bool) {
	endpoint := strings.TrimSpace(value)
	if endpoint == "" {
		return "", 0, false
	}
	index := strings.LastIndex(endpoint, ":")
	if index <= 0 {
		return "", 0, false
	}
	host := strings.TrimSpace(endpoint[:index])
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	port, err := strconv.Atoi(strings.TrimSpace(endpoint[index+1:]))
	if host == "" || err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// firstMapValue walks a chain of nested objects, returning nil if any is absent.
func firstMapValue(values map[string]any, keys ...string) map[string]any {
	current := values
	for _, key := range keys {
		if current == nil {
			return nil
		}
		current, _ = current[key].(map[string]any)
	}
	return current
}

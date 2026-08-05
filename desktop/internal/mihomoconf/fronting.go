package mihomoconf

// IP fronting, for the engine this app actually runs.
//
// Fronting reaches a server through a different address while still presenting
// its name: the connection goes to an IP that is not blocked, and the name the
// server needs to recognise the request travels in the TLS SNI or the Host
// header. The address changes; nothing about who the server thinks is calling
// does.
//
// The rules for which proxies can be fronted are the phone app's, and the same
// ones the Xray path here already applies: a proxy whose server is a name (not
// already an address), that carries TLS or an HTTP-shaped transport, and that
// is not using Reality — Reality pins the address into its handshake, so moving
// it breaks the connection rather than hiding it.

import (
	"net"
	"strings"
)

// FrontProxies returns the proxies with their addresses replaced by ip, leaving
// alone the ones fronting cannot be applied to.
//
// It reports how many were changed, because none being changed is worth knowing
// about: it means the address was accepted and had no effect.
func FrontProxies(proxies []Proxy, ip string) ([]Proxy, int) {
	address := net.ParseIP(strings.TrimSpace(ip))
	if address == nil || address.To4() == nil {
		return proxies, 0
	}

	fronted := make([]Proxy, 0, len(proxies))
	changed := 0
	for _, proxy := range proxies {
		next, ok := frontProxy(proxy, address.String())
		if ok {
			changed++
		}
		fronted = append(fronted, next)
	}
	return fronted, changed
}

// frontProxy rewrites one proxy, and reports whether it could.
func frontProxy(proxy Proxy, ip string) (Proxy, bool) {
	host := proxyHostname(proxy)
	if host == "" || net.ParseIP(host) != nil {
		// Nothing to preserve: an address has no name to keep presenting.
		return proxy, false
	}
	if _, reality := proxy["reality-opts"]; reality {
		return proxy, false
	}
	if !frontableTransport(proxy) {
		return proxy, false
	}

	next := make(Proxy, len(proxy)+2)
	for key, value := range proxy {
		next[key] = value
	}
	next["server"] = ip

	// The name has to keep travelling, or the server has no idea which site is
	// being asked for and answers with the wrong certificate, or not at all.
	if tlsEnabled(next) {
		if !hasStringValue(next, "servername") && !hasStringValue(next, "sni") {
			if _, trojan := next["password"]; trojan && next["type"] == "trojan" {
				next["sni"] = host
			} else {
				next["servername"] = host
			}
		}
	}
	setTransportHost(next, host)
	return next, true
}

// frontableTransport reports whether the proxy carries something that has a
// name in it to preserve — TLS, or one of the HTTP-shaped transports.
func frontableTransport(proxy Proxy) bool {
	switch strings.ToLower(strings.TrimSpace(stringValue(proxy, "type"))) {
	case "vless", "vmess", "trojan":
	default:
		return false
	}
	if tlsEnabled(proxy) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(stringValue(proxy, "network"))) {
	case "ws", "httpupgrade", "grpc", "h2", "http", "xhttp":
		return true
	}
	return false
}

func tlsEnabled(proxy Proxy) bool {
	if enabled, ok := proxy["tls"].(bool); ok && enabled {
		return true
	}
	// VMess carries it as a cipher-ish string in some links.
	return strings.EqualFold(strings.TrimSpace(stringValue(proxy, "security")), "tls")
}

// proxyHostname is the name this proxy is known by: whichever of the fields
// that can hold one does, preferring the ones a server actually reads.
func proxyHostname(proxy Proxy) string {
	for _, key := range []string{"servername", "sni"} {
		if value := stringValue(proxy, key); value != "" {
			return value
		}
	}
	if host := transportHost(proxy); host != "" {
		return host
	}
	return stringValue(proxy, "server")
}

// transportHost reads the Host header out of whichever transport options block
// this proxy has.
func transportHost(proxy Proxy) string {
	for _, key := range transportOptionKeys {
		opts, ok := proxy[key].(map[string]any)
		if !ok {
			continue
		}
		headers, ok := opts["headers"].(map[string]any)
		if !ok {
			continue
		}
		switch value := headers["Host"].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case []string:
			if len(value) > 0 && strings.TrimSpace(value[0]) != "" {
				return strings.TrimSpace(value[0])
			}
		case []any:
			if len(value) > 0 {
				if first, ok := value[0].(string); ok && strings.TrimSpace(first) != "" {
					return strings.TrimSpace(first)
				}
			}
		}
		if value := opts["host"]; value != nil {
			if host, ok := value.(string); ok && strings.TrimSpace(host) != "" {
				return strings.TrimSpace(host)
			}
		}
	}
	return ""
}

// setTransportHost puts the name into the transport's Host header when it has
// one and it is empty, so an HTTP-shaped transport still asks for the right site.
func setTransportHost(proxy Proxy, host string) {
	for _, key := range transportOptionKeys {
		opts, ok := proxy[key].(map[string]any)
		if !ok {
			continue
		}
		headers, ok := opts["headers"].(map[string]any)
		if !ok {
			headers = map[string]any{}
			opts["headers"] = headers
		}
		if existing, ok := headers["Host"].(string); ok && strings.TrimSpace(existing) != "" {
			continue
		}
		if existing, ok := headers["Host"].([]string); ok && len(existing) > 0 {
			continue
		}
		headers["Host"] = host
	}
}

var transportOptionKeys = []string{"ws-opts", "http-opts", "h2-opts", "httpupgrade-opts", "xhttp-opts"}

func stringValue(proxy Proxy, key string) string {
	value, _ := proxy[key].(string)
	return strings.TrimSpace(value)
}

func hasStringValue(proxy Proxy, key string) bool {
	return stringValue(proxy, key) != ""
}

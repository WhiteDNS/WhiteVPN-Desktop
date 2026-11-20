package mihomoconf

import (
	"regexp"
	"strings"
)

// Automatic ECH, as WhiteVPN for Android 1.8.0 does it: CDN TLS proxies get
// optional ECH unless the subscription already said something about ECH.
// Iran cuts CDN TLS without ECH after the handshake; optional ECH falls back to
// plain TLS in the core when the name publishes no ECH config.

var ipv4Literal = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// AutoECHEligible reports whether automatic ECH would be added to this proxy.
func AutoECHEligible(proxy Proxy) bool {
	if _, set := proxy["ech-opts"]; set {
		// Even `enable: false`: the subscription's own word stands.
		return false
	}
	if _, reality := proxy["reality-opts"]; reality {
		return false
	}
	switch strings.ToLower(stringValue(proxy, "type")) {
	case "trojan":
	case "vless", "vmess":
		if !boolValue(proxy["tls"]) {
			return false
		}
	default:
		return false
	}
	switch strings.ToLower(stringValue(proxy, "network")) {
	case "ws", "grpc", "xhttp":
	default:
		return false
	}
	for _, key := range []string{"servername", "sni", "server"} {
		if name := stringValue(proxy, key); name != "" {
			return !ipv4Literal.MatchString(name) && !strings.Contains(name, ":")
		}
	}
	return false
}

// ApplyAutoECH adds optional ECH to every eligible proxy. Eligible ones are
// copied, so the caller's parsed subscription is left as it was.
func ApplyAutoECH(proxies []Proxy, enabled bool) []Proxy {
	if !enabled {
		return proxies
	}
	out := make([]Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		if !AutoECHEligible(proxy) {
			out = append(out, proxy)
			continue
		}
		next := make(Proxy, len(proxy)+1)
		for k, v := range proxy {
			next[k] = v
		}
		next["ech-opts"] = map[string]any{"enable": true, "optional": true}
		out = append(out, next)
	}
	return out
}

// ECHEnabled reports whether a proxy, as it will be dialled, uses ECH.
func ECHEnabled(proxy Proxy) bool {
	opts, _ := proxy["ech-opts"].(map[string]any)
	return boolValue(opts["enable"])
}

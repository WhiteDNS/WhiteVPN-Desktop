package mihomoconf

import (
	"strings"

	"whitevpn-desktop/internal/fragment"
)

// ApplyFragments wraps TCP proxy dials. Datagram transports keep their own
// obfuscation. A fresh map keeps subscription caches and other attempts intact.
func ApplyFragments(proxies []Proxy, settings fragment.Settings) ([]Proxy, error) {
	if !settings.Enabled {
		return proxies, nil
	}
	settings, err := fragment.Validate(settings)
	if err != nil {
		return nil, err
	}
	stages, _ := fragment.Parse(settings.RawJSON)
	out := make([]Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		switch strings.ToLower(stringValue(proxy, "type")) {
		case "vless", "vmess", "trojan", "ss", "ssr", "socks5", "http", "anytls":
		default:
			out = append(out, proxy)
			continue
		}
		next := make(Proxy, len(proxy)+3)
		for k, v := range proxy {
			next[k] = v
		}
		delete(next, "fragment")
		next["fragments"] = stages
		if strings.EqualFold(stringValue(proxy, "type"), "vless") {
			if _, reality := proxy["reality-opts"]; reality {
				fp := strings.ToLower(stringValue(proxy, "client-fingerprint"))
				if fp == "" || fp == "none" || fp == "unsafe" {
					next["client-fingerprint"] = "chrome"
				}
			}
			if settings.ALPN != "" {
				next["alpn"] = strings.Split(settings.ALPN, ",")
			}
			if settings.CipherSuites != "" {
				next["cipher-suites"] = settings.CipherSuites
			}
		}
		out = append(out, next)
	}
	return out, nil
}

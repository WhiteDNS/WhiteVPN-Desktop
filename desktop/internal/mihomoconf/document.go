package mihomoconf

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Subscriptions come in two shapes and this package now reads both.
//
// The first is a list of share links — `vless://…` and friends — which is what
// the built-in catalogue ships and what every parser here was written for. The
// second is a whole mihomo configuration: `proxies:` with the engine's own
// schema, plus the provider's groups and rules. Panels that target Clash serve
// it, usually behind `?app=clash`.
//
// The second shape is, if anything, the easier one: it is already the language
// the engine speaks, so the proxies need no conversion at all. What it needed
// was for something to look inside it, which nothing did — a subscription in
// that shape was refused with "must contain V2Ray links or base64 encoded V2Ray
// links", which is true and useless.
//
// Both shapes end as []Proxy so that everything downstream — the node list, the
// Servers page, delay and speed tests, IP fronting, node selection — works the
// same way for both. One model, not two.

// ParseSubscription reads either shape and returns the proxies it holds,
// alongside the share link each came from where there was one.
//
// Share links are tried first because they are cheap to recognise and are what
// most subscriptions are. A document has no share links to report, so the
// sources come back empty for it rather than invented.
func ParseSubscription(body string) ([]Proxy, []string, error) {
	proxies, sources, linkErr := ConvertLinksWithSources(body)
	if linkErr == nil {
		return proxies, sources, nil
	}

	proxies, docErr := ParseDocument(body)
	if docErr == nil {
		return proxies, make([]string, len(proxies)), nil
	}

	if proxies, err := ParseSingBox(body); err == nil {
		return proxies, make([]string, len(proxies)), nil
	}
	if proxies, err := ParseXrayJSON(body); err == nil {
		return proxies, make([]string, len(proxies)), nil
	}

	// Base64 is a wrapper, not a format. ConvertLinks already unwraps it to look
	// for links; a document served the same way deserves the same treatment,
	// and providers do serve them that way.
	if decoded, ok := decodeBase64Text(strings.TrimSpace(body)); ok {
		if proxies, _, err := ParseSubscription(decoded); err == nil {
			return proxies, make([]string, len(proxies)), nil
		}
	}

	// Nothing read it. The link error leads because a subscription that is none
	// of these is far more often a broken link list than a broken document.
	return nil, nil, fmt.Errorf("%w (and it is not a mihomo, sing-box or Xray configuration either: %v)", linkErr, docErr)
}

// ParseDocument reads the `proxies` of a mihomo configuration.
//
// JSON is accepted as well as YAML because YAML is a superset of it and some
// panels serve JSON — the document that prompted this was `{"mixed-port": 7890,
// … "proxies": [...]}`. A detector that matched on a line beginning `proxies:`
// would have missed it, which is exactly what the previous one did.
func ParseDocument(body string) ([]Proxy, error) {
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("mihomoconf: the document is empty")
	}

	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(body), &document); err != nil {
		return nil, fmt.Errorf("mihomoconf: not a readable configuration: %w", err)
	}
	if len(document.Proxies) == 0 {
		return nil, fmt.Errorf("mihomoconf: the configuration has no proxies")
	}

	names := newNameRegistry()
	proxies := make([]Proxy, 0, len(document.Proxies))
	for _, entry := range document.Proxies {
		proxy := Proxy(entry)
		// A proxy the engine cannot dial is worse than one that is absent: it
		// takes a row on the Servers page and fails every test run against it.
		if !usableProxy(proxy) {
			continue
		}
		// Names have to be unique — they are how a node is chosen, measured and
		// stored — and a document is not obliged to make them so.
		proxy["name"] = names.register(proxy.Name())
		proxies = append(proxies, proxy)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("mihomoconf: the configuration has no usable proxies")
	}
	return proxies, nil
}

// usableProxy reports whether an entry has the parts the engine needs to dial
// it. The type is checked against nothing: mihomo supports more outbound types
// than this app converts links for, and a document naming one of them is a
// document that knows better than we do.
func usableProxy(proxy Proxy) bool {
	if strings.TrimSpace(proxy.Name()) == "" {
		return false
	}
	if kind, _ := proxy["type"].(string); strings.TrimSpace(kind) == "" {
		return false
	}
	if server, _ := proxy["server"].(string); strings.TrimSpace(server) == "" {
		return false
	}
	return proxyPortOf(proxy) > 0
}

// proxyPortOf reads a port that YAML may have decoded as any numeric kind.
func proxyPortOf(proxy Proxy) int {
	switch value := proxy["port"].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		var port int
		if _, err := fmt.Sscanf(value, "%d", &port); err == nil {
			return port
		}
	}
	return 0
}

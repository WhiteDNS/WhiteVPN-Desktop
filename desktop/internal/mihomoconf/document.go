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
	proxies, sources, _, err := ParseSubscriptionWithReport(body)
	return proxies, sources, err
}

// ParseSubscriptionWithReport also reports what the document held and this could
// not use, which is what makes a node count explainable.
//
// Only the links path fills the report in. The others read a list of proxies
// out of a structured document rather than a line at a time, so there is no
// per-line discard to count and an empty report is the honest answer.
func ParseSubscriptionWithReport(body string) ([]Proxy, []string, SkipReport, error) {
	proxies, sources, report, linkErr := ConvertLinksWithReport(body)
	if linkErr == nil {
		return proxies, sources, report, nil
	}

	proxies, docErr := ParseDocument(body)
	if docErr == nil {
		return proxies, make([]string, len(proxies)), SkipReport{}, nil
	}

	if proxies, err := ParseSingBox(body); err == nil {
		return proxies, make([]string, len(proxies)), SkipReport{}, nil
	}
	if proxies, err := ParseXrayJSON(body); err == nil {
		return proxies, make([]string, len(proxies)), SkipReport{}, nil
	}

	// Base64 is a wrapper, not a format. ConvertLinks already unwraps it to look
	// for links; a document served the same way deserves the same treatment,
	// and providers do serve them that way.
	if decoded, ok := decodeBase64Text(strings.TrimSpace(body)); ok {
		if proxies, _, report, err := ParseSubscriptionWithReport(decoded); err == nil {
			return proxies, make([]string, len(proxies)), report, nil
		}
	}

	// Nothing read it. Say what arrived rather than what was hoped for: the
	// commonest causes are a login page, an error page and an empty response,
	// and "must contain V2Ray links" describes none of them. What it *is* is
	// reported, never what it says — a subscription body carries credentials
	// and this message ends up in screenshots.
	return nil, nil, SkipReport{}, fmt.Errorf("this does not look like a subscription: %s", describeBody(body))
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

// describeBody says what a subscription body is without repeating what it
// says. The content is a credential; its shape is a diagnosis.
func describeBody(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return "the server returned nothing"
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "<!doctype html"), strings.HasPrefix(lower, "<html"):
		// Nearly always a login page or an error page behind the address.
		return fmt.Sprintf("the server returned a web page (%d bytes), not a subscription — check the address, and whether it needs to be signed in to", len(trimmed))
	case strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		return fmt.Sprintf("the server returned %d bytes of JSON with no proxies, outbounds or servers in it", len(trimmed))
	case strings.Contains(trimmed, "://"):
		return fmt.Sprintf("the server returned %d bytes containing links, but none of a kind this app can use", len(trimmed))
	default:
		return fmt.Sprintf("the server returned %d bytes that are neither share links nor a mihomo, sing-box or Xray configuration", len(trimmed))
	}
}

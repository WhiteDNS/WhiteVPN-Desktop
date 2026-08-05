package mihomoconf

import (
	"encoding/base64"
	"strings"
	"testing"
)

func init() {
	// Deterministic so that a WebSocket proxy's headers can be asserted on.
	pickUserAgent = func() string { return "test-agent" }
}

func convertOne(t *testing.T, link string) Proxy {
	t.Helper()
	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatalf("ConvertLinks(%q): %v", link, err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	return proxies[0]
}

func TestVlessRealityOverTCP(t *testing.T) {
	proxy := convertOne(t,
		"vless://11111111-2222-3333-4444-555555555555@example.com:443"+
			"?security=reality&sni=www.microsoft.com&pbk=abcdef&sid=00&fp=chrome&type=tcp&flow=XTLS-RPRX-VISION#Node%20One")

	if proxy["type"] != "vless" || proxy["server"] != "example.com" || proxy["port"] != 443 {
		t.Fatalf("unexpected endpoint: %#v", proxy)
	}
	if proxy["uuid"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("uuid not carried: %#v", proxy["uuid"])
	}
	if proxy.Name() != "Node One" {
		t.Fatalf("fragment should decode into the name, got %q", proxy.Name())
	}
	if proxy["tls"] != true || proxy["servername"] != "www.microsoft.com" {
		t.Fatalf("reality implies tls plus servername: %#v", proxy)
	}
	// Lowercased, because mihomo matches the flow name exactly.
	if proxy["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow should be lowercased, got %#v", proxy["flow"])
	}
	reality, ok := proxy["reality-opts"].(map[string]any)
	if !ok || reality["public-key"] != "abcdef" || reality["short-id"] != "00" {
		t.Fatalf("reality-opts wrong: %#v", proxy["reality-opts"])
	}
	// Absent packetEncoding means xudp, which is what the phone sends.
	if proxy["xudp"] != true {
		t.Fatalf("expected xudp by default: %#v", proxy)
	}
}

func TestVlessWebSocketCarriesPathHostAndEarlyData(t *testing.T) {
	proxy := convertOne(t,
		"vless://11111111-2222-3333-4444-555555555555@example.com:443"+
			"?security=tls&type=ws&path=%2Fdownload&host=cdn.example.com&ed=2048#WS")

	if proxy["network"] != "ws" {
		t.Fatalf("expected ws, got %#v", proxy["network"])
	}
	opts := proxy["ws-opts"].(map[string]any)
	if opts["path"] != "/download" {
		t.Fatalf("path should be percent-decoded, got %#v", opts["path"])
	}
	headers := opts["headers"].(map[string]any)
	if headers["Host"] != "cdn.example.com" || headers["User-Agent"] != "test-agent" {
		t.Fatalf("headers wrong: %#v", headers)
	}
	if opts["max-early-data"] != 2048 || opts["early-data-header-name"] != "Sec-WebSocket-Protocol" {
		t.Fatalf("early data not translated: %#v", opts)
	}
}

// httpupgrade shares the ws options but expresses early data as a different
// switch entirely, which is easy to get wrong by copying the ws branch.
func TestHttpUpgradeUsesFastOpenRatherThanMaxEarlyData(t *testing.T) {
	proxy := convertOne(t,
		"vless://11111111-2222-3333-4444-555555555555@example.com:443"+
			"?security=tls&type=httpupgrade&path=/up&ed=1#HU")

	opts := proxy["ws-opts"].(map[string]any)
	if opts["v2ray-http-upgrade-fast-open"] != true {
		t.Fatalf("expected fast-open for httpupgrade: %#v", opts)
	}
	if _, present := opts["max-early-data"]; present {
		t.Fatalf("max-early-data belongs to ws only: %#v", opts)
	}
}

// A tcp link with headerType=http is not tcp: it is mihomo's http transport.
func TestTcpWithHttpHeaderBecomesHttpTransport(t *testing.T) {
	proxy := convertOne(t,
		"vless://11111111-2222-3333-4444-555555555555@example.com:80"+
			"?type=tcp&headerType=http&path=/x&host=a.example.com#H")

	if proxy["network"] != "http" {
		t.Fatalf("expected http, got %#v", proxy["network"])
	}
	opts := proxy["http-opts"].(map[string]any)
	if paths, ok := opts["path"].([]string); !ok || len(paths) != 1 || paths[0] != "/x" {
		t.Fatalf("http path should be a list: %#v", opts["path"])
	}
}

func TestTrojanWithWebSocket(t *testing.T) {
	proxy := convertOne(t,
		"trojan://secretpass@example.com:443?type=ws&path=/tj&sni=a.example.com&allowInsecure=1#TJ")

	if proxy["type"] != "trojan" || proxy["password"] != "secretpass" {
		t.Fatalf("unexpected: %#v", proxy)
	}
	if proxy["sni"] != "a.example.com" || proxy["skip-cert-verify"] != true {
		t.Fatalf("tls fields wrong: %#v", proxy)
	}
	opts := proxy["ws-opts"].(map[string]any)
	if opts["path"] != "/tj" {
		t.Fatalf("ws path wrong: %#v", opts)
	}
}

func TestShadowsocksWithBase64Credentials(t *testing.T) {
	credentials := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:hunter2"))
	proxy := convertOne(t, "ss://"+credentials+"@example.com:8388#SS")

	if proxy["type"] != "ss" || proxy["cipher"] != "aes-256-gcm" || proxy["password"] != "hunter2" {
		t.Fatalf("credentials not decoded: %#v", proxy)
	}
	if proxy["server"] != "example.com" || proxy["port"] != 8388 {
		t.Fatalf("endpoint wrong: %#v", proxy)
	}
}

func TestLegacyVmessJSONForm(t *testing.T) {
	payload := `{"v":"2","ps":"VM","add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555",` +
		`"aid":"0","net":"ws","host":"cdn.example.com","path":"/vm","tls":"tls","scy":"auto"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

	proxy := convertOne(t, link)
	if proxy["type"] != "vmess" || proxy["server"] != "example.com" || proxy["port"] != 443 {
		t.Fatalf("unexpected: %#v", proxy)
	}
	// port and aid arrive as strings in this form and must become numbers.
	if proxy["alterId"] != 0 {
		t.Fatalf("alterId should be numeric zero: %#v", proxy["alterId"])
	}
	if proxy["tls"] != true {
		t.Fatalf("tls should be on: %#v", proxy)
	}
	opts := proxy["ws-opts"].(map[string]any)
	if opts["path"] != "/vm" {
		t.Fatalf("ws path wrong: %#v", opts)
	}
}

// Duplicate names would collapse into one proxy, because mihomo keys them by
// name. The phone app suffixes them; so must this.
func TestDuplicateNamesAreMadeUnique(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#Same"
	proxies, err := ConvertLinks(strings.Join([]string{link, link, link}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{proxies[0].Name(), proxies[1].Name(), proxies[2].Name()}
	want := []string{"Same", "Same-01", "Same-02"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names %v, want %v", got, want)
		}
	}
}

// The catalogue arrives base64-wrapped, and a bad line in the middle of it must
// not cost the user every node after it.
func TestBase64BodyAndMalformedLinesAreSkipped(t *testing.T) {
	body := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls#A",
		"vless://@b.example.com:443#missing-uuid",
		"not a link at all",
		"vless://11111111-2222-3333-4444-555555555555@c.example.com:0?security=tls#bad-port",
		"trojan://pw@d.example.com:443#D",
	}, "\n")

	proxies, err := ConvertLinks(base64.StdEncoding.EncodeToString([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 2 {
		names := []string{}
		for _, p := range proxies {
			names = append(names, p.Name())
		}
		t.Fatalf("expected the 2 good links, got %v", names)
	}
	if proxies[0].Name() != "A" || proxies[1].Name() != "D" {
		t.Fatalf("wrong survivors: %#v", proxies)
	}
}

// Hysteria2 was on this list until the desktop took it deliberately. The rest
// are still ignored: the engine cannot carry them, and a desktop connecting
// through a node it cannot carry would fail in a way nobody could explain.
func TestSchemesTheEngineCannotUseAreIgnored(t *testing.T) {
	body := strings.Join([]string{
		"tuic://uuid:pw@example.com:443#TUIC",
		"socks://user:pass@example.com:1080#SOCKS",
	}, "\n")

	if _, err := ConvertLinks(body); err == nil {
		t.Fatal("expected no usable proxies from schemes the engine cannot use")
	}
}

func TestEmptyInputIsAnError(t *testing.T) {
	if _, err := ConvertLinks("   "); err == nil {
		t.Fatal("expected an error for empty input")
	}
}

func TestIPv6LiteralEndpoint(t *testing.T) {
	proxy := convertOne(t,
		"vless://11111111-2222-3333-4444-555555555555@[2606:4700:4700::1111]:443?security=tls#V6")
	if proxy["server"] != "2606:4700:4700::1111" || proxy["port"] != 443 {
		t.Fatalf("IPv6 literal not parsed: %#v", proxy)
	}
}

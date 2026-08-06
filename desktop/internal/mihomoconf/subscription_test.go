package mihomoconf

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func base64Of(body string) string { return base64.StdEncoding.EncodeToString([]byte(body)) }

// The fixtures are real subscriptions from a BPB panel with every credential
// and hostname replaced. Their shape is the point: each of these was refused
// with "subscription must contain V2Ray links or base64 encoded V2Ray links",
// which was true and useless, and each is now read.
func fixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// One entry point, whatever the provider decided to serve. Everything after it
// — the Servers page, delay and speed tests, node selection, IP fronting —
// sees the same []Proxy and cannot tell the shapes apart.
func TestParseSubscriptionReadsEveryShape(t *testing.T) {
	links := "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=ws&security=tls#Alpha\n" +
		"trojan://pw@b.example.com:443?sni=b.example.com#Beta"

	for _, testCase := range []struct {
		name string
		body string
		want int
	}{
		{"share links", links, 2},
		{"mihomo document", fixture(t, "clash-normal.json"), 3},
		{"sing-box document", fixture(t, "singbox-normal.json"), 3},
		{"xray document list", fixture(t, "xray-normal.json"), 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			proxies, sources, err := ParseSubscription(testCase.body)
			if err != nil {
				t.Fatalf("ParseSubscription: %v", err)
			}
			if len(proxies) != testCase.want {
				t.Fatalf("got %d proxies, want %d", len(proxies), testCase.want)
			}
			// One source slot per proxy, always, so callers can index either
			// list without checking which shape it came from.
			if len(sources) != len(proxies) {
				t.Fatalf("got %d source slots for %d proxies", len(sources), len(proxies))
			}
			for i, proxy := range proxies {
				if proxy.Name() == "" {
					t.Fatalf("proxy %d has no name", i)
				}
				if server, _ := proxy["server"].(string); server == "" {
					t.Fatalf("proxy %q has no server", proxy.Name())
				}
				if proxyPortOf(proxy) <= 0 {
					t.Fatalf("proxy %q has no port", proxy.Name())
				}
				if kind, _ := proxy["type"].(string); kind == "" {
					t.Fatalf("proxy %q has no type", proxy.Name())
				}
			}
		})
	}
}

// Base64 is a wrapper, not a format, and providers wrap all of these in it.
func TestParseSubscriptionUnwrapsBase64(t *testing.T) {
	for _, name := range []string{"clash-normal.json", "singbox-normal.json", "xray-normal.json"} {
		plain, _, err := ParseSubscription(fixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		wrapped, _, err := ParseSubscription(base64Of(fixture(t, name)))
		if err != nil {
			t.Fatalf("%s wrapped in base64: %v", name, err)
		}
		if len(wrapped) != len(plain) {
			t.Fatalf("%s: %d proxies wrapped, %d plain", name, len(wrapped), len(plain))
		}
	}
}

// sing-box and Xray both put the TLS name in one place for trojan and another
// for everything else. Writing the wrong one is a handshake that fails with
// nothing to explain it.
func TestDocumentsPutTheTLSNameWhereTheProtocolExpectsIt(t *testing.T) {
	for _, name := range []string{"singbox-normal.json", "xray-normal.json"} {
		proxies, _, err := ParseSubscription(fixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, proxy := range proxies {
			kind, _ := proxy["type"].(string)
			if enabled, _ := proxy["tls"].(bool); !enabled {
				continue
			}
			_, hasSNI := proxy["sni"]
			_, hasServerName := proxy["servername"]
			if kind == "trojan" && !hasSNI {
				t.Fatalf("%s: trojan %q needs sni, got %#v", name, proxy.Name(), proxy)
			}
			if kind == "vless" && !hasServerName {
				t.Fatalf("%s: vless %q needs servername, got %#v", name, proxy.Name(), proxy)
			}
		}
	}
}

// Routing entries are not servers. A selector or a urltest taking a row on the
// Servers page would be a node that every test run fails against.
func TestSingBoxSkipsRoutingOutbounds(t *testing.T) {
	proxies, err := ParseSingBox(fixture(t, "singbox-normal.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, proxy := range proxies {
		switch proxy["type"] {
		case "selector", "urltest", "direct", "block", "dns":
			t.Fatalf("%q is routing, not a server", proxy.Name())
		}
	}
}

// Names are how a node is chosen, measured and remembered. A document is under
// no obligation to make them unique; this package is.
func TestDocumentNamesAreMadeUnique(t *testing.T) {
	document := `
proxies:
  - {name: Same, type: trojan, server: a.example.com, port: 443, password: pw}
  - {name: Same, type: trojan, server: b.example.com, port: 443, password: pw}
  - {name: Same, type: trojan, server: c.example.com, port: 443, password: pw}
`
	proxies, err := ParseDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, proxy := range proxies {
		if seen[proxy.Name()] {
			t.Fatalf("duplicate name %q", proxy.Name())
		}
		seen[proxy.Name()] = true
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 distinct names, got %d", len(seen))
	}
}

// A proxy the engine cannot dial is worse than one that is absent: it takes a
// row, fails every test, and looks like the app is broken.
func TestDocumentDropsUndialableProxies(t *testing.T) {
	document := `
proxies:
  - {name: Good, type: trojan, server: a.example.com, port: 443, password: pw}
  - {name: NoServer, type: trojan, port: 443}
  - {name: NoPort, type: trojan, server: b.example.com}
  - {name: NoType, server: c.example.com, port: 443}
  - {type: trojan, server: d.example.com, port: 443}
`
	proxies, err := ParseDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || proxies[0].Name() != "Good" {
		t.Fatalf("expected only the dialable one, got %#v", proxies)
	}
}

func TestParseSubscriptionRefusesWhatIsNeitherShape(t *testing.T) {
	for _, body := range []string{"", "   ", "this is not a subscription", "{}", "[]"} {
		if _, _, err := ParseSubscription(body); err == nil {
			t.Fatalf("expected %q to be refused", body)
		}
	}
}

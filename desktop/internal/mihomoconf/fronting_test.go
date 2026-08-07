package mihomoconf

import "testing"

func TestFrontProxiesReplacesTheAddressAndKeepsTheName(t *testing.T) {
	proxies := []Proxy{{
		"name": "one", "type": "vless", "server": "node.example.com", "port": 443,
		"tls": true, "network": "ws",
		"ws-opts": map[string]any{"path": "/", "headers": map[string]any{}},
	}}

	fronted, changed := FrontProxies(proxies, "203.0.113.5")
	if changed != 1 {
		t.Fatalf("expected the proxy to be fronted, got %d changed", changed)
	}
	proxy := fronted[0]
	if proxy["server"] != "203.0.113.5" {
		t.Fatalf("expected the address to be replaced, got %v", proxy["server"])
	}
	if proxy["servername"] != "node.example.com" {
		t.Fatalf("the name has to keep travelling in the SNI, got %v", proxy["servername"])
	}
	headers := proxy["ws-opts"].(map[string]any)["headers"].(map[string]any)
	if headers["Host"] != "node.example.com" {
		t.Fatalf("expected the Host header to carry the name, got %v", headers["Host"])
	}
	// The originals are not touched: a failed attempt has to be able to fall
	// back to them.
	if proxies[0]["server"] != "node.example.com" {
		t.Fatalf("the input was modified: %v", proxies[0]["server"])
	}
}

func TestFrontProxiesLeavesAloneWhatItCannotFront(t *testing.T) {
	cases := map[string]Proxy{
		"already an address": {"type": "vless", "server": "198.51.100.7", "tls": true},
		"reality pins the address": {
			"type": "vless", "server": "node.example.com", "tls": true,
			"reality-opts": map[string]any{"public-key": "k"},
		},
		"no tls and no http transport":    {"type": "vless", "server": "node.example.com", "network": "tcp"},
		"a type the phone does not front": {"type": "ss", "server": "node.example.com", "tls": true},
	}
	for name, proxy := range cases {
		t.Run(name, func(t *testing.T) {
			fronted, changed := FrontProxies([]Proxy{proxy}, "203.0.113.5")
			if changed != 0 {
				t.Fatalf("expected no change, got %d", changed)
			}
			if fronted[0]["server"] != proxy["server"] {
				t.Fatalf("the address was rewritten anyway: %v", fronted[0]["server"])
			}
		})
	}
}

func TestFrontProxiesIgnoresAnAddressItCannotUse(t *testing.T) {
	proxies := []Proxy{{"type": "vless", "server": "node.example.com", "tls": true}}
	for _, ip := range []string{"", "not-an-ip", "2001:db8::1"} {
		if _, changed := FrontProxies(proxies, ip); changed != 0 {
			t.Fatalf("expected %q to be ignored", ip)
		}
	}
}

// A name already set is the one the subscription chose; fronting must not
// overwrite it with the server address it happens to be replacing.
func TestFrontProxiesKeepsANameTheSubscriptionSet(t *testing.T) {
	proxies := []Proxy{{
		"type": "vless", "server": "node.example.com", "tls": true,
		"servername": "chosen.example.com", "network": "ws",
	}}
	fronted, changed := FrontProxies(proxies, "203.0.113.5")
	if changed != 1 {
		t.Fatalf("expected the proxy to be fronted, got %d", changed)
	}
	if fronted[0]["servername"] != "chosen.example.com" {
		t.Fatalf("expected the subscription's name to stand, got %v", fronted[0]["servername"])
	}
}

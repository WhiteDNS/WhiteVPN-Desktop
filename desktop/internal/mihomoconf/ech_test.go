package mihomoconf

import "testing"

// The cases of Android's connectionOptionsPatcherAddsOptionalEchOnlyToCdnTlsProxies
// and autoEchMarksOnlyEligibleProfilesAsEchEnabled, plus the edges of the rule.
func TestAutoECHEligibility(t *testing.T) {
	const document = `proxies:
  - name: WS
    type: vless
    server: 104.16.1.1
    port: 443
    tls: true
    network: ws
    servername: cdn.example.com
  - { name: Trojan gRPC, type: trojan, server: grpc.example.com, port: 443, network: grpc }
  - { name: Has ECH, type: vless, server: a.example.com, port: 443, tls: true, network: ws, ech-opts: { enable: false } }
  - { name: Reality, type: vless, server: r.example.com, port: 443, tls: true, network: xhttp, reality-opts: { public-key: k } }
  - { name: Plain WS, type: vmess, server: p.example.com, port: 80, network: ws }
  - { name: TCP TLS, type: trojan, server: t.example.com, port: 443 }
  - { name: IP only, type: vless, server: 1.2.3.4, port: 443, tls: true, network: ws }
  - { name: Explicit off, type: vless, server: off.example.com, port: 443, tls: true, network: ws, ech-opts: { enable: false } }
  - { name: IPv6 only, type: trojan, server: "2001:db8::1", port: 443, network: ws }
  - { name: VMess XHTTP, type: vmess, server: v.example.com, port: 443, tls: true, network: xhttp }
  - { name: VLESS TCP, type: vless, server: c.example.com, port: 443, tls: true, network: tcp }
  - { name: SNI wins, type: trojan, server: 1.2.3.4, sni: s.example.com, port: 443, network: ws }
  - { name: Servername first, type: vless, server: n.example.com, servername: 5.6.7.8, sni: s.example.com, port: 443, tls: true, network: grpc }
  - { name: Shadowsocks, type: ss, server: ss.example.com, port: 443, cipher: aes-128-gcm, password: pw, network: ws }
`
	want := map[string]bool{
		"WS": true, "Trojan gRPC": true, "Has ECH": false, "Reality": false,
		"Plain WS": false, "TCP TLS": false, "IP only": false, "Explicit off": false,
		"IPv6 only": false, "VMess XHTTP": true, "VLESS TCP": false, "SNI wins": true,
		"Servername first": false, "Shadowsocks": false,
	}
	proxies, err := ParseDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != len(want) {
		t.Fatalf("parsed %d proxies, want %d", len(proxies), len(want))
	}

	patched := ApplyAutoECH(proxies, true)
	for i, proxy := range patched {
		name := proxy.Name()
		if got := AutoECHEligible(proxies[i]); got != want[name] {
			t.Errorf("%s: eligible = %v, want %v", name, got, want[name])
		}
		if got := ECHEnabled(proxy); got != want[name] {
			t.Errorf("%s: ECH after patch = %v, want %v", name, got, want[name])
		}
		if want[name] {
			opts := proxy["ech-opts"].(map[string]any)
			if opts["enable"] != true || opts["optional"] != true {
				t.Errorf("%s: ech-opts = %#v", name, opts)
			}
			if _, touched := proxies[i]["ech-opts"]; touched {
				t.Errorf("%s: the parsed proxy was modified in place", name)
			}
		}
	}
	// The subscription's own `enable: false` stands.
	if opts := patched[2]["ech-opts"].(map[string]any); opts["enable"] != false || len(opts) != 1 {
		t.Errorf("Has ECH was overridden: %#v", opts)
	}

	for _, proxy := range ApplyAutoECH(proxies, false) {
		if ECHEnabled(proxy) {
			t.Errorf("%s: ECH with automatic ECH off", proxy.Name())
		}
	}
}

package mihomoconf

import (
	"reflect"
	"testing"
)

func TestConvertLinksReadsHysteria2(t *testing.T) {
	link := "hysteria2://sw0rdf1sh@node.example.com:8443?sni=node.example.com&insecure=1&alpn=h3&obfs=salamander&obfs-password=shhh#JP%20Fast"

	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one proxy, got %d", len(proxies))
	}
	proxy := proxies[0]
	want := map[string]any{
		"name":             "JP Fast",
		"type":             "hysteria2",
		"server":           "node.example.com",
		"port":             8443,
		"password":         "sw0rdf1sh",
		"sni":              "node.example.com",
		"skip-cert-verify": true,
		"obfs":             "salamander",
		"obfs-password":    "shhh",
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxy[key], value) {
			t.Errorf("%s = %#v, want %#v", key, proxy[key], value)
		}
	}
	if alpn, ok := proxy["alpn"].([]string); !ok || len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("alpn = %#v", proxy["alpn"])
	}
}

// hy2:// is the same thing under a shorter name.
func TestConvertLinksAcceptsTheShortHysteriaScheme(t *testing.T) {
	proxies, err := ConvertLinks("hy2://pass@node.example.com:443#Short")
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || proxies[0]["type"] != "hysteria2" {
		t.Fatalf("unexpected result: %#v", proxies)
	}
}

// Obfuscation without its password does nothing but break the handshake.
func TestConvertLinksDropsObfuscationWithoutItsPassword(t *testing.T) {
	proxies, err := ConvertLinks("hysteria2://pass@node.example.com:443?obfs=salamander#No%20Password")
	if err != nil {
		t.Fatal(err)
	}
	if _, present := proxies[0]["obfs"]; present {
		t.Fatalf("expected obfs to be dropped, got %#v", proxies[0])
	}
}

func TestConvertLinksStillSkipsWhatTheEngineCannotUse(t *testing.T) {
	for _, link := range []string{
		"tuic://uuid:pass@node.example.com:443#Tuic",
		"socks://dXNlcjpwYXNz@node.example.com:1080#Socks",
	} {
		if _, err := ConvertLinks(link); err == nil {
			t.Fatalf("expected %q to yield nothing", link)
		}
	}
}

// Fronting rewrites the address of nodes that carry a name to preserve.
// Hysteria2 is QUIC with its own certificate, so it is left alone.
func TestFrontProxiesLeavesHysteria2Alone(t *testing.T) {
	proxies, err := ConvertLinks("hysteria2://pass@node.example.com:443?sni=node.example.com#H2")
	if err != nil {
		t.Fatal(err)
	}
	if _, changed := FrontProxies(proxies, "203.0.113.5"); changed != 0 {
		t.Fatalf("expected hysteria2 to be left alone, got %d changed", changed)
	}
}

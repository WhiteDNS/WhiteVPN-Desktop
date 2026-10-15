package mihomoconf

import (
	"reflect"
	"testing"

	"whitevpn-desktop/internal/fragment"
)

func TestFragmentsPreserveSourceAndDatagramTransports(t *testing.T) {
	proxies := []Proxy{
		{"name": "reality", "type": "vless", "reality-opts": map[string]any{"public-key": "key"}, "client-fingerprint": "unsafe", "fragment": map[string]any{"length": "5"}},
		{"name": "tls", "type": "vless", "client-fingerprint": "firefox", "alpn": []string{"h2"}},
		{"name": "trojan", "type": "trojan", "alpn": []string{"h2"}},
		{"name": "warp", "type": "wireguard"}, {"name": "quic", "type": "hysteria2"},
	}
	s := fragment.Default()
	s.Enabled = true
	got, err := ApplyFragments(proxies, s)
	if err != nil {
		t.Fatal(err)
	}
	if got[0]["client-fingerprint"] != "chrome" || got[1]["client-fingerprint"] != "firefox" {
		t.Fatal("REALITY fingerprint compatibility lost")
	}
	if _, ok := got[0]["fragment"]; ok {
		t.Fatal("conflicting fragment alias retained")
	}
	if !reflect.DeepEqual(got[1]["alpn"], []string{"http/1.1"}) || got[1]["cipher-suites"] != s.CipherSuites {
		t.Fatal("TLS overrides not applied")
	}
	if !reflect.DeepEqual(got[2]["alpn"], []string{"h2"}) {
		t.Fatal("VLESS TLS overrides leaked to another protocol")
	}
	for _, i := range []int{3, 4} {
		if !reflect.DeepEqual(got[i], proxies[i]) {
			t.Fatal("UDP proxy changed")
		}
	}
	if proxies[0]["client-fingerprint"] != "unsafe" || proxies[1]["fragments"] != nil {
		t.Fatal("cached proxies mutated")
	}
	s.ALPN, s.CipherSuites = "", ""
	got, err = ApplyFragments(proxies, s)
	if err != nil || !reflect.DeepEqual(got[1]["alpn"], []string{"h2"}) || got[1]["cipher-suites"] != nil {
		t.Fatal("blank overrides must preserve server settings")
	}
	s.Enabled = false
	got, err = ApplyFragments(proxies, s)
	if err != nil || !reflect.DeepEqual(got, proxies) {
		t.Fatal("disabled fragments changed proxies")
	}
}

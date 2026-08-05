package mihomoconf

import (
	"reflect"
	"testing"
)

// The shape a real subscription ships, measured 2026-08-05: the private key in
// the user info, the peer as host and port, the rest as query parameters.
func TestConvertLinksReadsWireGuard(t *testing.T) {
	link := "wireguard://0HWFA24ETSHemoGTj2ZDbhL0VrUEef50y2q6FlLPgF8%3D@node.example.com:51820" +
		"?address=10.0.0.2%2F32%2Cfd00%3A%3A2%2F128&mtu=1420&publickey=vUdHmo14D%2BYe7tJO5yj%2B09LOzM1g0%2F8NJ0aytxQMawQ%3D#wg"

	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one proxy, got %d", len(proxies))
	}
	want := map[string]any{
		"name":        "wg",
		"type":        "wireguard",
		"server":      "node.example.com",
		"port":        51820,
		"private-key": "0HWFA24ETSHemoGTj2ZDbhL0VrUEef50y2q6FlLPgF8=",
		"public-key":  "vUdHmo14D+Ye7tJO5yj+09LOzM1g0/8NJ0aytxQMawQ=",
		// Split by family, because the engine keeps them in separate fields.
		"ip":   "10.0.0.2/32",
		"ipv6": "fd00::2/128",
		"mtu":  1420,
		"udp":  true,
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxies[0][key], value) {
			t.Errorf("%s = %#v, want %#v", key, proxies[0][key], value)
		}
	}
}

// The spellings differ between the clients that emit these links, and a
// subscription is not ours to correct.
func TestConvertLinksReadsWireGuardUnderItsOtherNames(t *testing.T) {
	link := "wg://node.example.com:51820?private_key=cHJpdmF0ZQ%3D%3D&peer_public_key=cHVibGlj&ip=10.7.0.2" +
		"&psk=cHJlc2hhcmVk&allowed_ips=0.0.0.0%2F0%2C%3A%3A%2F0&persistentkeepalive=25&reserved=1%2C2%2C3#Alt"

	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	proxy := proxies[0]
	if proxy["private-key"] != "cHJpdmF0ZQ==" || proxy["public-key"] != "cHVibGlj" {
		t.Fatalf("keys were not read: %#v", proxy)
	}
	if proxy["pre-shared-key"] != "cHJlc2hhcmVk" || proxy["persistent-keepalive"] != 25 {
		t.Fatalf("peer options were not read: %#v", proxy)
	}
	if !reflect.DeepEqual(proxy["allowed-ips"], []string{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("allowed-ips = %#v", proxy["allowed-ips"])
	}
	if !reflect.DeepEqual(proxy["reserved"], []int{1, 2, 3}) {
		t.Fatalf("reserved = %#v", proxy["reserved"])
	}
}

// A tunnel needs both halves of the key pair. One of them is not half a node,
// it is a proxy that fails at the first packet, and a row the user cannot tell
// apart from a working one.
func TestConvertLinksSkipsWireGuardMissingAKey(t *testing.T) {
	for _, link := range []string{
		"wireguard://cHJpdmF0ZQ%3D%3D@node.example.com:51820?address=10.0.0.2%2F32#No%20Peer",
		"wireguard://node.example.com:51820?publickey=cHVibGlj&address=10.0.0.2%2F32#No%20Private",
	} {
		if _, err := ConvertLinks(link); err == nil {
			t.Fatalf("expected %q to yield nothing", link)
		}
	}
}

// Fronting moves a node's address while keeping the name it presents. WireGuard
// presents no name — it is raw UDP authenticated by a key — so there is nothing
// to preserve and moving the address would only break the peer.
func TestFrontProxiesLeavesWireGuardAlone(t *testing.T) {
	proxies, err := ConvertLinks("wireguard://cHJpdmF0ZQ%3D%3D@node.example.com:51820?publickey=cHVibGlj&address=10.0.0.2%2F32#WG")
	if err != nil {
		t.Fatal(err)
	}
	if _, changed := FrontProxies(proxies, "203.0.113.5"); changed != 0 {
		t.Fatalf("expected wireguard to be left alone, got %d changed", changed)
	}
}

// Reserved is three bytes or nothing: the engine refuses any other length, and
// refusing it here costs one node rather than the whole configuration.
func TestConvertLinksDropsAMalformedWireGuardReserved(t *testing.T) {
	for _, reserved := range []string{"1%2C2", "1%2C2%2C300", "a%2Cb%2Cc"} {
		proxies, err := ConvertLinks("wireguard://cHJpdmF0ZQ%3D%3D@node.example.com:51820?publickey=cHVibGlj&reserved=" + reserved + "#R")
		if err != nil {
			t.Fatal(err)
		}
		if value, present := proxies[0]["reserved"]; present {
			t.Fatalf("reserved=%s should have been dropped, got %#v", reserved, value)
		}
	}
}

package mihomoconf

import "testing"

func wireGuardProxy(name string) Proxy {
	return Proxy{"name": name, "type": "wireguard", "server": "a.example.com", "port": 51820}
}

func vlessProxy(name string) Proxy {
	return Proxy{"name": name, "type": "vless", "server": "b.example.com", "port": 443}
}

func TestNoisePadsWireGuardOnly(t *testing.T) {
	proxies := []Proxy{wireGuardProxy("wg"), vlessProxy("vless")}

	out, changed := ApplyAmneziaNoise(proxies, AmneziaNoise{Enabled: true, Count: 5, MinSize: 50, MaxSize: 100})
	if changed != 1 {
		t.Fatalf("expected one proxy padded, got %d", changed)
	}

	options, ok := out[0]["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatalf("the WireGuard proxy was not padded: %#v", out[0])
	}
	if options["jc"] != 5 || options["jmin"] != 50 || options["jmax"] != 100 {
		t.Fatalf("unexpected options: %#v", options)
	}
	// mihomo has nowhere to put this on a vless proxy, and writing it would be a
	// key the engine does not know on a type that cannot use it.
	if _, present := out[1]["amnezia-wg-option"]; present {
		t.Fatalf("a vless proxy should be untouched: %#v", out[1])
	}
}

// A subscription of vless nodes is one where this setting changes nothing, and
// the count is how the interface can say so instead of leaving someone to wonder.
func TestNoiseReportsWhenItReachesNothing(t *testing.T) {
	_, changed := ApplyAmneziaNoise([]Proxy{vlessProxy("a"), vlessProxy("b")},
		AmneziaNoise{Enabled: true, Count: 5, MinSize: 50, MaxSize: 100})
	if changed != 0 {
		t.Fatalf("expected nothing padded, got %d", changed)
	}
}

func TestNoiseOffChangesNothing(t *testing.T) {
	proxies := []Proxy{wireGuardProxy("wg")}
	out, changed := ApplyAmneziaNoise(proxies, AmneziaNoise{Enabled: false, Count: 5, MinSize: 50, MaxSize: 100})
	if changed != 0 {
		t.Fatalf("expected nothing padded, got %d", changed)
	}
	if _, present := out[0]["amnezia-wg-option"]; present {
		t.Fatal("the proxy should be untouched")
	}
}

// Numbers that would tell mihomo to add no junk are the same as the switch being
// off, and writing the option to say nothing only makes the config harder to read.
func TestNoiseIgnoresNumbersThatSayNothing(t *testing.T) {
	for _, noise := range []AmneziaNoise{
		{Enabled: true, Count: 0, MinSize: 50, MaxSize: 100},
		{Enabled: true, Count: 5, MinSize: 0, MaxSize: 100},
		// A largest smaller than the smallest is not a range.
		{Enabled: true, Count: 5, MinSize: 100, MaxSize: 50},
	} {
		if _, changed := ApplyAmneziaNoise([]Proxy{wireGuardProxy("wg")}, noise); changed != 0 {
			t.Errorf("%#v should have been ignored", noise)
		}
	}
}

// The proxies come from the subscription; a setting must not edit what the
// subscription said.
func TestNoiseDoesNotAlterTheProxiesItWasGiven(t *testing.T) {
	original := wireGuardProxy("wg")
	proxies := []Proxy{original}

	ApplyAmneziaNoise(proxies, AmneziaNoise{Enabled: true, Count: 5, MinSize: 50, MaxSize: 100})

	if _, present := original["amnezia-wg-option"]; present {
		t.Fatal("the caller's proxy was modified in place")
	}
}

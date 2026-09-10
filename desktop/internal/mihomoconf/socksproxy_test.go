package mihomoconf

import (
	"reflect"
	"testing"
)

func TestConvertLinksReadsSocks(t *testing.T) {
	proxy := convertOne(t, "socks5://user:s3cret@node.example.com:1080#SOCKS%20One")
	want := map[string]any{
		"name":     "SOCKS One",
		"type":     "socks5",
		"server":   "node.example.com",
		"port":     1080,
		"username": "user",
		"password": "s3cret",
		"udp":      true,
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxy[key], value) {
			t.Errorf("%s = %#v, want %#v", key, proxy[key], value)
		}
	}
}

// base64("user:s3cret") as a single blob, which is the form the phone reads and
// the one generators emit most often.
func TestSocksReadsBase64Credentials(t *testing.T) {
	proxy := convertOne(t, "socks://dXNlcjpzM2NyZXQ=@node.example.com:1080#Blob")
	if proxy["username"] != "user" || proxy["password"] != "s3cret" {
		t.Fatalf("credentials = %#v / %#v", proxy["username"], proxy["password"])
	}
}

func TestSocksAcceptsABareUsername(t *testing.T) {
	proxy := convertOne(t, "socks://user@node.example.com:1080#Bare")
	if proxy["username"] != "user" {
		t.Fatalf("username = %#v", proxy["username"])
	}
	if password, present := proxy["password"]; present {
		t.Fatalf("password = %#v, want it absent", password)
	}
}

func TestSocksWithoutCredentialsIsStillANode(t *testing.T) {
	proxy := convertOne(t, "socks5://node.example.com:1080#Open")
	if proxy["type"] != "socks5" || proxy["port"] != 1080 {
		t.Fatalf("unexpected proxy: %#v", proxy)
	}
	if _, present := proxy["username"]; present {
		t.Fatalf("expected no username: %#v", proxy)
	}
}

// A plus in a password is a plus. QueryUnescape reads it as a space, which
// produces a credential that fails authentication with nothing to show why.
func TestSocksKeepsAPlusInThePassword(t *testing.T) {
	proxy := convertOne(t, "socks5://user:pa+ss@node.example.com:1080#Plus")
	if proxy["password"] != "pa+ss" {
		t.Fatalf("password = %#v, want %q", proxy["password"], "pa+ss")
	}
}

// UDP is on unless the link says otherwise: socks5 carries it by ASSOCIATE, and
// a node silently downgraded to TCP breaks the calls that are the reason to ask.
func TestSocksUDPIsOnUnlessRefused(t *testing.T) {
	if convertOne(t, "socks5://node.example.com:1080?udp=0#Off")["udp"] != false {
		t.Fatal("udp=0 should turn it off")
	}
	if convertOne(t, "socks5://node.example.com:1080?udp=true#On")["udp"] != true {
		t.Fatal("udp=true should leave it on")
	}
}

func TestConvertLinksReadsHTTPProxy(t *testing.T) {
	proxy := convertOne(t, "http-proxy://user:s3cret@proxy.example.com:8080#HTTP")
	want := map[string]any{
		"name":     "HTTP",
		"type":     "http",
		"server":   "proxy.example.com",
		"port":     8080,
		"username": "user",
		"password": "s3cret",
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxy[key], value) {
			t.Errorf("%s = %#v, want %#v", key, proxy[key], value)
		}
	}
	// mihomo's HTTP outbound has no UDP at all; CONNECT carries streams only.
	if value, present := proxy["udp"]; present {
		t.Errorf("udp = %#v, want it absent", value)
	}
	if value, present := proxy["tls"]; present {
		t.Errorf("tls = %#v, want it absent for http-proxy", value)
	}
}

func TestHTTPSProxyCarriesTLS(t *testing.T) {
	proxy := convertOne(t, "https-proxy://proxy.example.com:8443?sni=proxy.example.com&insecure=1#HTTPS")
	if proxy["tls"] != true || proxy["sni"] != "proxy.example.com" || proxy["skip-cert-verify"] != true {
		t.Fatalf("unexpected proxy: %#v", proxy)
	}
}

// A subscription is a document full of URLs — a provider's own address, a
// banner, a link in a comment. Reading any of them as a node would invent
// servers out of a web page, so only the unambiguous schemes are accepted.
func TestBareHTTPURLsAreNotProxies(t *testing.T) {
	for _, link := range []string{
		"https://example.com/subscription?token=abc",
		"http://example.com:8080/page",
	} {
		if _, err := ConvertLinks(link); err == nil {
			t.Fatalf("expected %q to yield nothing", link)
		}
	}
}

// An unnamed node would take "" from the registry and the next would take
// "-01", so a list of them reads as a column of blanks.
func TestUnnamedProxiesFallBackToTheirAddress(t *testing.T) {
	if name := convertOne(t, "socks5://node.example.com:1080")["name"]; name != "node.example.com:1080" {
		t.Fatalf("name = %#v", name)
	}
}

package mihomoconf

import (
	"reflect"
	"testing"
)

func TestConvertLinksReadsAnyTls(t *testing.T) {
	link := "anytls://sw0rdf1sh@node.example.com:8443/?sni=node.example.com&insecure=1&alpn=h2,http/1.1&hpkp=deadbeef#DE%20One"

	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one proxy, got %d", len(proxies))
	}
	proxy := proxies[0]
	want := map[string]any{
		"name":             "DE One",
		"type":             "anytls",
		"server":           "node.example.com",
		"port":             8443,
		"password":         "sw0rdf1sh",
		"sni":              "node.example.com",
		"skip-cert-verify": true,
		"fingerprint":      "deadbeef",
		"udp":              true,
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxy[key], value) {
			t.Errorf("%s = %#v, want %#v", key, proxy[key], value)
		}
	}
	if alpn, ok := proxy["alpn"].([]string); !ok || !reflect.DeepEqual(alpn, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn = %#v", proxy["alpn"])
	}
}

// The user:password form, which anytls-go and mihomo's own converter both
// accept. Sending the server "user:secret" would be sending it a credential it
// never issued.
func TestAnyTlsTakesThePasswordHalfOfAUserPassPair(t *testing.T) {
	proxy := convertOne(t, "anytls://user:s3cret@node.example.com:443#Pair")
	if proxy["password"] != "s3cret" {
		t.Fatalf("password = %#v, want %q", proxy["password"], "s3cret")
	}
}

// A colon inside a password is written %3A, and decoding before the split would
// turn it into the separator and cut the password in half.
func TestAnyTlsKeepsAnEncodedColonInsideThePassword(t *testing.T) {
	proxy := convertOne(t, "anytls://pa%3Assword@node.example.com:443#Encoded")
	if proxy["password"] != "pa:ssword" {
		t.Fatalf("password = %#v, want %q", proxy["password"], "pa:ssword")
	}
}

// anytls has no anonymous mode, so a link with no secret is one the server
// would only ever refuse.
func TestAnyTlsWithoutACredentialIsSkipped(t *testing.T) {
	if _, err := ConvertLinks("anytls://node.example.com:443#Bare"); err == nil {
		t.Fatal("expected a link with no credential to yield nothing")
	}
}

// peer is the older spelling of sni, and the phone reads it.
func TestAnyTlsFallsBackFromSniToPeer(t *testing.T) {
	proxy := convertOne(t, "anytls://pass@node.example.com:443?peer=front.example.com#Peer")
	if proxy["sni"] != "front.example.com" {
		t.Fatalf("sni = %#v", proxy["sni"])
	}
}

// Unlike vless and trojan, no uTLS fingerprint is invented: it changes the
// handshake the server sees, and anytls links do not carry fp by convention.
func TestAnyTlsAddsNoClientFingerprintOfItsOwn(t *testing.T) {
	proxy := convertOne(t, "anytls://pass@node.example.com:443#Plain")
	if value, present := proxy["client-fingerprint"]; present {
		t.Fatalf("client-fingerprint = %#v, want it absent", value)
	}

	asked := convertOne(t, "anytls://pass@node.example.com:443?fp=chrome#Asked")
	if asked["client-fingerprint"] != "chrome" {
		t.Fatalf("client-fingerprint = %#v, want %q", asked["client-fingerprint"], "chrome")
	}
}

// The report is what tells somebody a node count is the catalogue's and not
// this parser's, so anytls has to stop being counted as unsupported.
func TestAnyTlsIsNoLongerReportedAsUnsupported(t *testing.T) {
	_, _, report, err := ConvertLinksWithReport("anytls://pass@node.example.com:443#Counted")
	if err != nil {
		t.Fatal(err)
	}
	if report.Converted != 1 || report.Skipped() != 0 {
		t.Fatalf("converted %d of %d links: %#v", report.Converted, report.Links, report)
	}
	if count := report.Unsupported["anytls"]; count != 0 {
		t.Fatalf("anytls still counted unsupported %d times", count)
	}
}

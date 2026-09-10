package profiles

import (
	"strings"
	"testing"

	"whitevpn-desktop/internal/mihomoconf"
)

// The seam this closes. Manual configs reach the engine by being exported back
// to links and read by mihomoconf, and until socks and the HTTP proxy schemes
// were added there, the form offered two protocols whose configs were stored,
// listed on the Servers page, and then dropped on the way out — a socks-only
// list could not connect at all, and a mixed one lost the node with no error.
func TestManualProxyConfigsReachTheEngine(t *testing.T) {
	for _, testCase := range []struct {
		link string
		want string
	}{
		{"socks://user:pass@node.example.com:1080#Socks", "socks5"},
		{"socks5://user:pass@node.example.com:1080#Socks5", "socks5"},
		{"http-proxy://user:pass@proxy.example.com:8080#HTTP", "http"},
		{"https-proxy://user:pass@proxy.example.com:8443#HTTPS", "http"},
	} {
		imported, err := ParseV2RayProfileImports(testCase.link)
		if err != nil {
			t.Errorf("%s: import: %v", testCase.link, err)
			continue
		}
		body, err := ExportV2RayProfiles(imported)
		if err != nil {
			t.Errorf("%s: export: %v", testCase.link, err)
			continue
		}
		proxies, err := mihomoconf.ConvertLinks(body)
		if err != nil {
			t.Errorf("%s: exported as %q, which the engine converter refused: %v", testCase.link, body, err)
			continue
		}
		if len(proxies) != 1 || proxies[0]["type"] != testCase.want {
			t.Errorf("%s: exported as %q, converted to %#v", testCase.link, body, proxies)
			continue
		}
		if proxies[0]["username"] != "user" || proxies[0]["password"] != "pass" {
			t.Errorf("%s: credentials lost: %#v", testCase.link, proxies[0])
		}
	}
}

// A mixed list is the quieter failure: the count on the Servers page keeps
// agreeing with itself while a node goes missing from the connection.
func TestAMixedManualListLosesNothing(t *testing.T) {
	imported, err := ParseV2RayProfileImports(strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls#VLESS",
		"socks://user:pass@b.example.com:1080#Socks",
		"http-proxy://user:pass@c.example.com:8080#HTTP",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := ExportV2RayProfiles(imported)
	if err != nil {
		t.Fatal(err)
	}

	proxies, _, report, err := mihomoconf.ConvertLinksWithReport(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != len(imported) {
		t.Fatalf("%d configs became %d proxies: %+v", len(imported), len(proxies), report)
	}
	if report.Skipped() != 0 {
		t.Fatalf("skipped %d of %d: %+v", report.Skipped(), report.Links, report)
	}
}

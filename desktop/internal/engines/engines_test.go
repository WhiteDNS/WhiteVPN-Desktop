package engines

import (
	"strings"
	"testing"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/session"
)

// TorEngineConfigTest.localSocksRouteExplicitlyDisablesUdpAndDirectFallback and
// routingOverridesPreserveTcpOnlyPolicy, through the real renderer.
func TestEngineRouteIsSocksOnlyAndRejectsUDP(t *testing.T) {
	body, err := RuntimeYAML(12345)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "type: socks5") || !strings.Contains(body, "udp: false") || strings.Contains(body, "DIRECT") || !strings.Contains(body, "12345") {
		t.Fatalf("runtime yaml = %s", body)
	}
	doc, candidates, err := session.PrepareConfig(session.Options{Subscription: body, RejectUDP: true,
		Bypass: []string{"psiphon-windows-amd64.exe"}, Direct: mihomoconf.DirectRoute{Domains: []string{"example.ir"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0] != ProxyName {
		t.Fatalf("candidates = %v", candidates)
	}
	if strings.Count(doc, "type: socks5") != 1 || !strings.Contains(doc, "server: 127.0.0.1") || !strings.Contains(doc, "udp: false") {
		t.Fatalf("engine route must hold the local socks5 proxy only:\n%s", doc)
	}
	bypass := strings.Index(doc, "PROCESS-NAME,psiphon-windows-amd64.exe,DIRECT")
	direct := strings.Index(doc, "example.ir")
	reject := strings.Index(doc, "NETWORK,UDP,REJECT")
	match := strings.Index(doc, "MATCH,"+mihomoconf.SelectGroup)
	if bypass < 0 || direct < 0 || reject < 0 || match < 0 || !(bypass < direct && direct < reject && reject < match) {
		t.Fatalf("rule order bypass=%d direct=%d reject=%d match=%d:\n%s", bypass, direct, reject, match, doc)
	}
	if !strings.Contains(doc, "find-process-mode: strict") {
		t.Fatal("process bypass needs process lookup")
	}
	if _, err := RuntimeYAML(0); err == nil {
		t.Fatal("port 0 accepted")
	}
}

func TestSubscriptionRoutesAreUnchanged(t *testing.T) {
	doc, _, err := session.PrepareConfig(session.Options{Subscription: "socks5://node.example.com:1080#One"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "NETWORK,UDP,REJECT") || strings.Contains(doc, "PROCESS-NAME") || !strings.Contains(doc, "find-process-mode: off") {
		t.Fatalf("subscription route gained engine rules:\n%s", doc)
	}
}

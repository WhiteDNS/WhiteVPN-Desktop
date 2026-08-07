package mihomoconf

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func sampleProxies(t *testing.T) []Proxy {
	t.Helper()
	proxies, err := ConvertLinks(strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=reality&pbk=k&sid=00#Alpha",
		"trojan://password@b.example.com:443?type=ws&path=/x#Beta",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return proxies
}

func parseYAML(t *testing.T, document string) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n---\n%s", err, document)
	}
	return parsed
}

func TestBuildProxiesYAMLProducesGroupsAndACatchAllRule(t *testing.T) {
	document, err := BuildProxiesYAML(sampleProxies(t), SplitTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseYAML(t, document)

	proxies, _ := parsed["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}

	groups, _ := parsed["proxy-groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("expected the select and auto groups, got %d", len(groups))
	}
	selectGroup := groups[0].(map[string]any)
	if selectGroup["name"] != SelectGroup || selectGroup["type"] != "select" {
		t.Fatalf("unexpected select group: %#v", selectGroup)
	}
	// The auto group has to be the first entry, or a fresh install starts pinned
	// to one arbitrary server instead of picking the fastest.
	members := selectGroup["proxies"].([]any)
	if members[0] != AutoGroup {
		t.Fatalf("auto group should lead the selector, got %#v", members)
	}
	if len(members) != 3 {
		t.Fatalf("selector should offer auto plus every node, got %#v", members)
	}

	autoGroup := groups[1].(map[string]any)
	if autoGroup["type"] != "url-test" || autoGroup["url"] != DelayTestURL {
		t.Fatalf("unexpected auto group: %#v", autoGroup)
	}

	// Without a rule nothing matches and the tunnel carries no traffic.
	rules, _ := parsed["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,"+SelectGroup {
		t.Fatalf("unexpected rules: %#v", rules)
	}
}

func TestBuildProxiesYAMLDropsDuplicateNames(t *testing.T) {
	proxies := []Proxy{
		{"name": "Same", "type": "vless", "server": "a.example.com", "port": 443},
		{"name": "Same", "type": "vless", "server": "b.example.com", "port": 443},
		{"name": "Other", "type": "vless", "server": "c.example.com", "port": 443},
	}
	document, err := BuildProxiesYAML(proxies, SplitTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseYAML(t, document)
	if got := len(parsed["proxies"].([]any)); got != 2 {
		t.Fatalf("expected the duplicate to be dropped, got %d proxies", got)
	}
}

func TestBuildProxiesYAMLRefusesAnEmptySet(t *testing.T) {
	if _, err := BuildProxiesYAML(nil, SplitTunnel{}); err == nil {
		t.Fatal("expected an error with no proxies")
	}
}

// The desktop's tunnel comes from configuration, unlike the phone's, which
// arrives as a file descriptor. Getting this wrong produces an app that runs and
// simply never tunnels anything.
func TestRenderEnablesTunAndContainsIPv6(t *testing.T) {
	document := Render("", Options{Secret: "s3cret", ProxyGroup: SelectGroup, Tun: DefaultTunOptions()})
	parsed := parseYAML(t, document)

	tun := parsed["tun"].(map[string]any)
	if tun["enable"] != true || tun["auto-route"] != true {
		t.Fatalf("tunnel must be on with auto-route: %#v", tun)
	}
	if tun["stack"] != "gvisor" {
		t.Fatalf("gvisor is required by the build; got %#v", tun["stack"])
	}
	// Hijacking 53 is what stops a program with a hard-coded resolver from
	// bypassing the tunnel's DNS.
	if hijack, _ := tun["dns-hijack"].([]any); len(hijack) != 1 || hijack[0] != "any:53" {
		t.Fatalf("dns-hijack wrong: %#v", tun["dns-hijack"])
	}
	// v6 is carried rather than ignored: Windows has no equivalent of Android's
	// implicit refusal to route what VpnService did not claim.
	if parsed["ipv6"] != true {
		t.Fatalf("ipv6 should be on: %#v", parsed["ipv6"])
	}
	if addresses, _ := tun["inet6-address"].([]any); len(addresses) != 1 {
		t.Fatalf("the tunnel needs a v6 address to win the route: %#v", tun["inet6-address"])
	}
}

// The DNS leak this was shipped with, and the reason dns-hijack alone is not the
// answer.
//
// Hijacking catches queries that enter the tunnel. A query to the resolver on
// the local network never enters it: the route to that subnet is directly
// connected on the physical adapter and beats the 0.0.0.0/1 pair the tunnel
// installs. So every lookup went to the home router in the clear, and a leak
// test showed the user's own ISP — in tunnel mode only, because through a proxy
// the machine never resolves anything itself.
//
// If this ever goes back to false, that leak returns and nothing else in the
// suite notices.
func TestRenderKeepsDNSInsideTheTunnel(t *testing.T) {
	document := Render("", Options{Secret: "s3cret", ProxyGroup: SelectGroup, Tun: DefaultTunOptions()})
	tun := parseYAML(t, document)["tun"].(map[string]any)

	if tun["strict-route"] != true {
		t.Fatalf("without strict-route, DNS to a resolver on the local network leaves the tunnel: %#v", tun["strict-route"])
	}
}

// It follows the tunnel: with nothing routed there is nothing to keep inside,
// and the filters would only be blocking the machine's own DNS.
func TestRenderLeavesStrictRouteOffWithTheTunnel(t *testing.T) {
	tun := DefaultTunOptions()
	tun.StrictRoute = false
	document := Render("", Options{Secret: "s", ProxyGroup: SelectGroup, Tun: tun})

	parsed := parseYAML(t, document)["tun"].(map[string]any)
	if parsed["strict-route"] != false {
		t.Fatalf("expected strict-route to follow the option: %#v", parsed["strict-route"])
	}
}

func TestRenderCanLeaveTunOff(t *testing.T) {
	document := Render("", Options{Secret: "s"})
	parsed := parseYAML(t, document)
	tun := parsed["tun"].(map[string]any)
	if tun["enable"] != false {
		t.Fatalf("expected the tunnel off: %#v", tun)
	}
	if parsed["ipv6"] != false {
		t.Fatalf("without a tunnel there is nothing to carry v6 through: %#v", parsed["ipv6"])
	}
}

func TestRenderDNSModes(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		options   Options
		wantFirst string
		wantCount int
	}{
		{"automatic offers both families", Options{ProxyGroup: SelectGroup}, "https://1.1.1.1/dns-query" + "#" + SelectGroup, 4},
		{"doh puts the user's server first", Options{DNSPrivacy: DNSOverHTTPS, DoHURL: "https://dns.example/dq", ProxyGroup: SelectGroup}, "https://dns.example/dq#" + SelectGroup, 3},
		{"dot puts the user's server first", Options{DNSPrivacy: DNSOverTLS, DoTEndpoint: "tls://dns.example:853", ProxyGroup: SelectGroup}, "tls://dns.example:853#" + SelectGroup, 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parsed := parseYAML(t, Render("", testCase.options))
			dns := parsed["dns"].(map[string]any)
			servers := dns["nameserver"].([]any)
			if len(servers) != testCase.wantCount {
				t.Fatalf("expected %d servers, got %#v", testCase.wantCount, servers)
			}
			if servers[0] != testCase.wantFirst {
				t.Fatalf("first server %#v, want %q", servers[0], testCase.wantFirst)
			}
		})
	}
}

// A user's own server appearing again among the fallbacks would have it queried
// twice.
func TestRenderDoesNotRepeatTheUsersOwnResolver(t *testing.T) {
	parsed := parseYAML(t, Render("", Options{DNSPrivacy: DNSOverHTTPS, DoHURL: DefaultDoHURL}))
	dns := parsed["dns"].(map[string]any)
	servers := dns["nameserver"].([]any)
	if len(servers) != 2 {
		t.Fatalf("expected the duplicate to be collapsed, got %#v", servers)
	}
}

// Pointing DNS at a group that does not exist breaks resolution outright, so
// respect-rules has to follow whether there is a group at all.
func TestRespectRulesFollowsTheProxyGroup(t *testing.T) {
	with := parseYAML(t, Render("", Options{ProxyGroup: SelectGroup}))
	if with["dns"].(map[string]any)["respect-rules"] != true {
		t.Fatal("respect-rules should be on when a group exists")
	}
	without := parseYAML(t, Render("", Options{}))
	if without["dns"].(map[string]any)["respect-rules"] != false {
		t.Fatal("respect-rules should be off without a group")
	}
	servers := without["dns"].(map[string]any)["nameserver"].([]any)
	if strings.Contains(servers[0].(string), "#") {
		t.Fatalf("no group means no group suffix: %#v", servers[0])
	}
}

// Whatever a subscription says about the keys the runtime owns, the app's values
// must win — and leaving both in would let the engine take either.
func TestRenderStripsSubscriptionOverrides(t *testing.T) {
	subscription := strings.Join([]string{
		"mixed-port: 9999",
		"external-controller-unix: /tmp/provider.sock",
		"listeners:",
		"  - name: provider-listener",
		"    type: socks",
		"    port: 9998",
		"mode: global",
		"dns:",
		"  enable: false",
		"  nameserver:",
		"    - 9.9.9.9",
		"proxies:",
		"  - name: Keep",
		"    type: vless",
		"rules:",
		"  - MATCH,Keep",
	}, "\n")

	parsed := parseYAML(t, Render(subscription, Options{MixedPort: 2080, Secret: "s"}))

	if parsed["mixed-port"] != 2080 {
		t.Fatalf("subscription's port should not survive: %#v", parsed["mixed-port"])
	}
	if parsed["mode"] != "rule" {
		t.Fatalf("subscription's mode should not survive: %#v", parsed["mode"])
	}
	if _, ok := parsed["listeners"]; ok {
		t.Fatalf("subscription listeners must not survive: %#v", parsed["listeners"])
	}
	if _, ok := parsed["external-controller-unix"]; ok {
		t.Fatalf("subscription control sockets must not survive: %#v", parsed["external-controller-unix"])
	}
	dns := parsed["dns"].(map[string]any)
	if dns["enable"] != true {
		t.Fatalf("the subscription's whole dns block should have gone: %#v", dns)
	}
	// Everything the runtime does not own must be left exactly as it was.
	if len(parsed["proxies"].([]any)) != 1 {
		t.Fatalf("subscription proxies were lost: %#v", parsed["proxies"])
	}
	if len(parsed["rules"].([]any)) != 1 {
		t.Fatalf("subscription rules were lost: %#v", parsed["rules"])
	}
}

func TestRenderBindsInternalDNSOnlyToLoopback(t *testing.T) {
	parsed := parseYAML(t, Render("", Options{}))
	dns := parsed["dns"].(map[string]any)
	if dns["listen"] != "127.0.0.1:1053" {
		t.Fatalf("DNS must not bind to the LAN: %#v", dns["listen"])
	}
}

func TestStripTopLevelKeysLeavesNestedOccurrencesAlone(t *testing.T) {
	document := strings.Join([]string{
		"proxies:",
		"  - name: A",
		"    tun: nested-value-must-stay",
		"tun:",
		"  enable: true",
		"rules:",
		"  - MATCH,A",
	}, "\n")

	stripped := StripTopLevelKeys(document, map[string]bool{"tun": true})
	if strings.Contains(stripped, "enable: true") {
		t.Fatalf("top-level tun block survived:\n%s", stripped)
	}
	if !strings.Contains(stripped, "nested-value-must-stay") {
		t.Fatalf("a nested key of the same name was removed:\n%s", stripped)
	}
	if !strings.Contains(stripped, "MATCH,A") {
		t.Fatalf("content after the stripped block was lost:\n%s", stripped)
	}
}

// A secret containing a quote would otherwise end the YAML string early and
// produce a config the engine rejects.
func TestSecretIsEscaped(t *testing.T) {
	parsed := parseYAML(t, Render("", Options{Secret: "it's a 'secret'"}))
	if parsed["secret"] != "it's a 'secret'" {
		t.Fatalf("secret did not round trip: %#v", parsed["secret"])
	}
}

func TestFullConfigFromLinksParses(t *testing.T) {
	proxiesYAML, err := BuildProxiesYAML(sampleProxies(t), SplitTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseYAML(t, Render(proxiesYAML, Options{
		Secret:     "s3cret",
		ProxyGroup: SelectGroup,
		Tun:        DefaultTunOptions(),
	}))

	for _, key := range []string{"proxies", "proxy-groups", "rules", "dns", "tun", "mixed-port", "external-controller"} {
		if _, present := parsed[key]; !present {
			t.Fatalf("finished config is missing %q", key)
		}
	}
}

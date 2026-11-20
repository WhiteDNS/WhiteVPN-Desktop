package mihomoconf

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// buildExitChain is the one-subscription chain this app used to build — node 1
// Automatic, node 2 fixed, both in one list — through the planner that now
// builds every chain. An empty exit is no chain.
func buildExitChain(proxies []Proxy, split SplitTunnel, exit string) (string, []string, error) {
	if exit == "" {
		return BuildProxiesYAMLWithRouting(proxies, Routing{Split: split})
	}
	planned, chain, err := PlanChain([]ChainSource{{ID: "sub", Name: "Sub", Proxies: proxies}},
		ChainHop{}, ChainHop{Ref: ChainRef{"sub", exit}})
	if err != nil {
		return "", nil, err
	}
	return BuildProxiesYAMLWithRouting(planned, Routing{Split: split, Chain: chain})
}

func fixedHop(subscription, node string) ChainHop {
	return ChainHop{Ref: ChainRef{subscription, node}}
}

// proxyOf builds the phone test's proxy() fixture.
func proxyOf(name, kind string, fields ...any) Proxy {
	proxy := Proxy{"name": name, "type": kind, "server": name + ".example", "port": 443}
	for i := 0; i+1 < len(fields); i += 2 {
		proxy[fields[i].(string)] = fields[i+1]
	}
	return proxy
}

func planDocument(t *testing.T, sources []ChainSource, entry, exit ChainHop) (map[string]any, []string) {
	t.Helper()
	planned, chain, err := PlanChain(sources, entry, exit)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	out, firstHop, err := BuildProxiesYAMLWithRouting(planned, Routing{Chain: chain})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out), &document); err != nil {
		t.Fatalf("the generated config is not YAML: %v", err)
	}
	return document, firstHop
}

func proxyNamed(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	proxies, _ := document["proxies"].([]any)
	for _, entry := range proxies {
		proxy, _ := entry.(map[string]any)
		if proxy["name"] == name {
			return proxy
		}
	}
	t.Fatalf("no proxy named %q in %v", name, proxies)
	return nil
}

// Every rule of the phone's MihomoProxyBlock.requiresUdpDialer and
// supportsUdpDialing, one row each.
func TestUDPDialerRulesMatchThePhone(t *testing.T) {
	cases := []struct {
		name     string
		proxy    Proxy
		requires bool
		supports bool
	}{
		{"tcp vless", proxyOf("a", "vless"), false, false},
		{"udp vless", proxyOf("a", "vless", "udp", true), false, true},
		{"wireguard", proxyOf("a", "wireguard", "udp", true), true, true},
		{"wireguard without udp", proxyOf("a", "wireguard"), true, false},
		{"hysteria", proxyOf("a", "hysteria"), true, true},
		{"hysteria2", proxyOf("a", "hysteria2"), true, true},
		{"hy2", proxyOf("a", "hy2"), true, true},
		{"tuic", proxyOf("a", "tuic"), true, true},
		{"juicity", proxyOf("a", "juicity"), true, false},
		{"shadowquic", proxyOf("a", "shadowquic"), true, true},
		{"network quic", proxyOf("a", "vless", "network", "quic"), true, false},
		{"network h3", proxyOf("a", "vless", "network", "H3"), true, false},
		{"network kcp", proxyOf("a", "vless", "network", "kcp"), true, false},
		{"network mkcp", proxyOf("a", "vless", "network", "mkcp"), true, false},
		{"transport udp", proxyOf("a", "vless", "transport", "UDP"), true, false},
		{"openvpn udp", proxyOf("a", "openvpn"), true, true},
		{"openvpn tcp", proxyOf("a", "openvpn", "proto", "tcp"), false, true},
		{"openvpn tcp-client", proxyOf("a", "openvpn", "proto", "TCP-client"), false, true},
		{"masque h3", proxyOf("a", "masque"), true, false},
		{"masque h2", proxyOf("a", "masque", "network", "H2"), false, false},
		{"ss udp", proxyOf("a", "ss", "udp", true), true, true},
		{"shadowsocks udp", proxyOf("a", "shadowsocks", "udp", true), true, true},
		{"ssr udp", proxyOf("a", "ssr", "udp", true), true, true},
		{"shadowsocksr udp", proxyOf("a", "shadowsocksr", "udp", true), true, true},
		{"socks5 udp", proxyOf("a", "socks5", "udp", true), true, true},
		{"gost-relay udp", proxyOf("a", "gost-relay", "udp", true), true, true},
		{"ss udp as a string", proxyOf("a", "ss", "udp", "true"), true, true},
		{"ss udp-over-tcp", proxyOf("a", "ss", "udp", true, "udp-over-tcp", true), false, true},
		{"socks5 udp-over-stream", proxyOf("a", "socks5", "udp", true, "udp-over-stream", true), false, true},
		{"ss without udp", proxyOf("a", "ss"), false, false},
		{"trojan udp is not a native relay", proxyOf("a", "trojan", "udp", true), false, true},
	}
	for _, c := range cases {
		if got := requiresUDPDialer(c.proxy); got != c.requires {
			t.Errorf("%s: requiresUDPDialer = %v, want %v", c.name, got, c.requires)
		}
		if got := supportsUDPDialing(c.proxy); got != c.supports {
			t.Errorf("%s: supportsUDPDialing = %v, want %v", c.name, got, c.supports)
		}
	}
	if supportsUDPDialing(nil) {
		t.Error("nothing carries nothing")
	}
}

// Off, No node 2: the config is exactly the one-hop one.
func TestNoChainIsThePlainConnection(t *testing.T) {
	plain, plainNames, err := BuildProxiesYAMLWithRouting(chainProxies(), Routing{})
	if err != nil {
		t.Fatal(err)
	}
	unchained, names, err := BuildProxiesYAMLWithRouting(chainProxies(), Routing{Chain: Chain{}})
	if err != nil {
		t.Fatal(err)
	}
	if plain != unchained || !reflect.DeepEqual(plainNames, names) {
		t.Fatal("an inactive chain changed the configuration")
	}
}

// Two link subscriptions, both naming a node "Germany 01": the names are made
// unique, and each end is the node from the list it was chosen in.
func TestTwoSubscriptionsWithCollidingNames(t *testing.T) {
	first, err := ConvertLinks("vless://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&type=tcp#Germany%2001")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConvertLinks("trojan://secret@two.example:443?sni=two.example#Germany%2001")
	if err != nil {
		t.Fatal(err)
	}
	sources := []ChainSource{{ID: "one", Name: "Provider one", Proxies: first}, {ID: "two", Name: "Provider two", Proxies: second}}

	document, firstHop := planDocument(t, sources, fixedHop("one", "Germany 01"), fixedHop("two", "Germany 01"))
	if !reflect.DeepEqual(firstHop, []string{"Germany 01"}) {
		t.Fatalf("node 1 should be the first list's node, alone: %v", firstHop)
	}
	if entry := proxyNamed(t, document, "Germany 01"); entry["server"] != "one.example" || entry["dialer-proxy"] != nil {
		t.Fatalf("node 1 is not the first list's node, dialled directly: %v", entry)
	}
	exit := proxyNamed(t, document, ChainExitName)
	if exit["server"] != "two.example" || exit["dialer-proxy"] != SelectGroup {
		t.Fatalf("node 2 is not the second list's node dialled through node 1: %v", exit)
	}
	rules, _ := document["rules"].([]any)
	if rules[len(rules)-1] != "MATCH,"+ChainExitName {
		t.Fatalf("traffic should leave through node 2: %v", rules)
	}

	// Automatic node 1 draws from both lists, so the second Germany 01 is
	// qualified with the list it came from rather than replacing the first.
	exitSource := ChainSource{ID: "exit", Name: "Exit", Proxies: []Proxy{proxyOf("exit", "trojan")}}
	document, firstHop = planDocument(t, append(sources, exitSource), ChainHop{}, fixedHop("exit", "exit"))
	if !reflect.DeepEqual(firstHop, []string{"Germany 01", "Provider two · Germany 01"}) {
		t.Fatalf("expected both lists' nodes, the repeat qualified: %v", firstHop)
	}
	if proxyNamed(t, document, "Provider two · Germany 01")["server"] != "two.example" {
		t.Fatal("the qualified name is not the second list's node")
	}
}

// WARP is a YAML subscription with one wireguard proxy; as node 1 under a link
// node 2 it is the dialer the exit goes through, and it carries UDP for a
// datagram exit too.
func TestAWireGuardDocumentAsNode1(t *testing.T) {
	warp, err := ParseDocument("proxies:\n  - {name: WARP, type: wireguard, server: 162.159.192.5, port: 2408, private-key: a, public-key: b, ip: 172.16.0.2, udp: true}\n")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ConvertLinks("vless://11111111-1111-1111-1111-111111111111@pub.example:443?security=tls&type=ws&path=%2F#Public")
	if err != nil {
		t.Fatal(err)
	}
	sources := []ChainSource{{ID: "warp", Name: "WARP", Proxies: warp}, {ID: "pub", Name: "Public", Proxies: public}}
	document, firstHop := planDocument(t, sources, fixedHop("warp", "WARP"), ChainHop{})
	if !reflect.DeepEqual(firstHop, []string{"WARP"}) {
		t.Fatalf("node 1 should be WARP: %v", firstHop)
	}
	if exit := proxyNamed(t, document, ChainExitName); exit["server"] != "pub.example" || exit["dialer-proxy"] != SelectGroup {
		t.Fatalf("the public node should leave through WARP: %v", exit)
	}
}

// A YAML subscription's own dialer-proxy chain survives, renamed with the
// proxies it names, at either end.
func TestAnInnerDialerChainIsKept(t *testing.T) {
	imported := ChainSource{ID: "imp", Name: "Imported", Proxies: []Proxy{
		proxyOf("transport", "vless", "udp", true),
		proxyOf("tunnel", "wireguard", "udp", true, "dialer-proxy", "transport"),
	}}
	// The other list has a "transport" of its own, so the names collide.
	other := ChainSource{ID: "oth", Name: "Other", Proxies: []Proxy{proxyOf("transport", "trojan", "udp", true)}}

	exit := ChainSource{ID: "exit", Name: "Exit", Proxies: []Proxy{proxyOf("exit", "trojan")}}

	document, firstHop := planDocument(t, []ChainSource{other, imported, exit}, ChainHop{}, fixedHop("exit", "exit"))
	if !reflect.DeepEqual(firstHop, []string{"transport", "Imported · transport", "tunnel"}) {
		t.Fatalf("node 1 should draw from both lists: %v", firstHop)
	}
	tunnel := proxyNamed(t, document, "tunnel")
	if tunnel["dialer-proxy"] != "Imported · transport" {
		t.Fatalf("the tunnel should still dial its own transport, renamed: %v", tunnel)
	}
	if inner := proxyNamed(t, document, "Imported · transport"); inner["type"] != "vless" || inner["dialer-proxy"] != nil {
		t.Fatalf("the imported transport is not its own: %v", inner)
	}
	if theirs := proxyNamed(t, document, "transport"); theirs["type"] != "trojan" {
		t.Fatalf("the other list's transport kept its name: %v", theirs)
	}

	// As node 2 the closure is copied whole: its outermost proxy dials node 1.
	document, _ = planDocument(t, []ChainSource{other, imported}, fixedHop("oth", "transport"), fixedHop("imp", "tunnel"))
	if inner := proxyNamed(t, document, ChainExitName+" · Imported · transport"); inner["dialer-proxy"] != SelectGroup {
		t.Fatalf("node 2's own transport should dial through node 1: %v", inner)
	}
	if exit := proxyNamed(t, document, ChainExitName); exit["type"] != "wireguard" || exit["dialer-proxy"] != ChainExitName+" · Imported · transport" {
		t.Fatalf("node 2 should reach its server through its own transport: %v", exit)
	}
}

// A dialer-proxy naming a group, a loop, or a TCP hop under a UDP one inside a
// subscription is not something a chain can carry, so it is not offered.
func TestUnchainableConfigsAreNotSelectable(t *testing.T) {
	source := ChainSource{ID: "s", Proxies: []Proxy{
		proxyOf("through-group", "vless", "dialer-proxy", "Main"),
		proxyOf("loop-a", "vless", "dialer-proxy", "loop-b"),
		proxyOf("loop-b", "vless", "dialer-proxy", "loop-a"),
		proxyOf("tcp", "vless"),
		proxyOf("wg-over-tcp", "wireguard", "udp", true, "dialer-proxy", "tcp"),
	}}
	if got := ChainSelectable(source); !reflect.DeepEqual(got, map[string]bool{"tcp": true}) {
		t.Fatalf("only the plain node can be a hop: %v", got)
	}
}

// The phone's pickerIssuesExplainWhichNodesCannotFillASlot, plus the shared
// inner proxy.
func TestPickerIssues(t *testing.T) {
	warp := ChainSource{ID: "warp", Proxies: []Proxy{proxyOf("WARP", "wireguard", "udp", true)}}
	public := ChainSource{ID: "pub", Proxies: []Proxy{proxyOf("tcp", "vless"), proxyOf("udp", "vless", "udp", true)}}
	sources := []ChainSource{warp, public}
	ref := func(sub, node string) ChainRef { return ChainRef{sub, node} }

	// Node 1 is a TCP-only VLESS: WARP cannot be node 2, the UDP-capable one can.
	issues := ChainPickerIssues(sources, false, fixedHop("pub", "tcp"))
	if issues[ref("warp", "WARP")] != ChainIssueUDP || issues[ref("pub", "tcp")] != ChainIssueSame {
		t.Fatalf("unexpected node 2 issues: %v", issues)
	}
	if _, ok := issues[ref("pub", "udp")]; ok {
		t.Fatal("a TCP node 2 needs nothing from node 1")
	}

	// WARP as node 1 accepts any public node 2.
	issues = ChainPickerIssues(sources, false, fixedHop("warp", "WARP"))
	if len(issues) != 1 || issues[ref("warp", "WARP")] != ChainIssueSame {
		t.Fatalf("WARP should only rule itself out: %v", issues)
	}

	// Picking node 1 against a fixed WARP node 2 rules out the TCP-only node.
	issues = ChainPickerIssues(sources, true, fixedHop("warp", "WARP"))
	if issues[ref("pub", "tcp")] != ChainIssueUDP {
		t.Fatalf("a TCP-only node 1 cannot carry WARP: %v", issues)
	}
	if _, ok := issues[ref("pub", "udp")]; ok {
		t.Fatal("a UDP-capable node 1 can carry WARP")
	}

	// Two configs of one list sharing an inner proxy.
	shared := ChainSource{ID: "shared", Proxies: []Proxy{
		proxyOf("transport", "vless", "udp", true),
		proxyOf("tunnel", "wireguard", "udp", true, "dialer-proxy", "transport"),
	}}
	issues = ChainPickerIssues([]ChainSource{shared}, true, fixedHop("shared", "tunnel"))
	if issues[ref("shared", "transport")] != ChainIssueShared {
		t.Fatalf("the transport is inside the tunnel already: %v", issues)
	}

	// The same server listed by two providers is the same config.
	twin := ChainSource{ID: "twin", Proxies: []Proxy{proxyOf("tcp", "vless")}}
	issues = ChainPickerIssues([]ChainSource{public, twin}, false, fixedHop("pub", "tcp"))
	if issues[ref("twin", "tcp")] != ChainIssueSame {
		t.Fatalf("one server under two names is still one server: %v", issues)
	}

	// An Automatic or missing other node blocks nothing.
	if issues := ChainPickerIssues(sources, false, ChainHop{}); len(issues) != 0 {
		t.Fatalf("Automatic should block nothing: %v", issues)
	}
	if issues := ChainPickerIssues(sources, false, fixedHop("gone", "x")); len(issues) != 0 {
		t.Fatalf("a node that is not there should block nothing: %v", issues)
	}
}

// A saved pair that cannot work is refused with the reason, not built into a
// tunnel that carries nothing.
func TestAnIncompatibleFixedPairIsRefused(t *testing.T) {
	tcp := ChainSource{ID: "tcp", Proxies: []Proxy{proxyOf("tcp", "vless")}}
	warp := ChainSource{ID: "warp", Proxies: []Proxy{proxyOf("WARP", "wireguard", "udp", true)}}
	shared := ChainSource{ID: "shared", Proxies: []Proxy{
		proxyOf("transport", "vless", "udp", true),
		proxyOf("tunnel", "wireguard", "udp", true, "dialer-proxy", "transport"),
	}}
	cases := []struct {
		entry, exit ChainHop
		want        string
	}{
		{fixedHop("tcp", "tcp"), fixedHop("warp", "WARP"), "UDP"},
		{fixedHop("tcp", "tcp"), fixedHop("tcp", "tcp"), "same config"},
		{fixedHop("shared", "transport"), fixedHop("shared", "tunnel"), "inner proxy"},
		{fixedHop("tcp", "gone"), fixedHop("warp", "WARP"), "not in its subscription"},
	}
	for _, c := range cases {
		_, _, err := PlanChain([]ChainSource{tcp, warp, shared}, c.entry, c.exit)
		var chainErr *ChainError
		if !errors.As(err, &chainErr) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v → %v: want a chain error about %q, got %v", c.entry, c.exit, c.want, err)
		}
	}
	// The other way round works: WARP carries a TCP node 2.
	if _, _, err := PlanChain([]ChainSource{tcp, warp}, fixedHop("warp", "WARP"), fixedHop("tcp", "tcp")); err != nil {
		t.Fatal(err)
	}
}

// An Automatic node 2 is every compatible config, each dialling node 1, under
// a url-test group traffic leaves through.
func TestAnAutomaticNode2IsAURLTestGroupOfCopies(t *testing.T) {
	tcp := ChainSource{ID: "tcp", Name: "TCP", Proxies: []Proxy{proxyOf("tcp", "vless")}}
	pool := ChainSource{ID: "pool", Name: "Pool", Proxies: []Proxy{
		proxyOf("a", "trojan"), proxyOf("b", "vless"), proxyOf("wg", "wireguard", "udp", true),
	}}
	document, firstHop := planDocument(t, []ChainSource{tcp, pool}, fixedHop("tcp", "tcp"), ChainHop{})
	if !reflect.DeepEqual(firstHop, []string{"tcp"}) {
		t.Fatalf("node 1 is the fixed one: %v", firstHop)
	}
	members := groupMembers(t, document, ChainExitName)
	want := []string{ChainExitName + " · a", ChainExitName + " · b"}
	if !reflect.DeepEqual(members, want) {
		t.Fatalf("node 2 should be the TCP configs other than node 1: %v", members)
	}
	if groupNamed(t, document, ChainExitName)["type"] != "url-test" {
		t.Fatal("an Automatic node 2 is chosen by the engine")
	}
	for _, name := range want {
		if proxyNamed(t, document, name)["dialer-proxy"] != SelectGroup {
			t.Fatalf("%s does not dial node 1", name)
		}
	}

	// Both Automatic: node 1 cannot be relied on to carry UDP, so the
	// wireguard node is not offered as node 2.
	document, _ = planDocument(t, []ChainSource{tcp, pool}, ChainHop{}, ChainHop{})
	for _, member := range groupMembers(t, document, ChainExitName) {
		if strings.HasSuffix(member, " · wg") {
			t.Fatal("a UDP node 2 over a node 1 that may be TCP only")
		}
	}
}

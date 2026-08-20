package mihomoconf

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func chainProxies() []Proxy {
	return []Proxy{
		{"name": "TCP One", "type": "vless", "server": "a.example.com", "port": 443},
		{"name": "TCP Two", "type": "trojan", "server": "b.example.com", "port": 443},
		{"name": "UDP One", "type": "hysteria2", "server": "c.example.com", "port": 443},
		// udp: true as parseWireGuard sets it. A WireGuard proxy relays UDP, so
		// it can carry a datagram protocol for the hop above it.
		{"name": "Wire One", "type": "wireguard", "server": "d.example.com", "port": 51820, "udp": true},
	}
}

func renderChain(t *testing.T, chain Chain) map[string]any {
	t.Helper()
	out, err := BuildProxiesYAMLWithChain(chainProxies(), SplitTunnel{}, chain)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out), &document); err != nil {
		t.Fatalf("the generated config is not YAML: %v", err)
	}
	return document
}

func groupNamed(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	groups, _ := document["proxy-groups"].([]any)
	for _, entry := range groups {
		group, _ := entry.(map[string]any)
		if group["name"] == name {
			return group
		}
	}
	t.Fatalf("no group named %q", name)
	return nil
}

func groupMembers(t *testing.T, document map[string]any, name string) []string {
	t.Helper()
	raw, _ := groupNamed(t, document, name)["proxies"].([]any)
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		out = append(out, entry.(string))
	}
	return out
}

// Without a chain nothing about the config changes.
func TestNoChainLeavesTheConfigAsItWas(t *testing.T) {
	document := renderChain(t, Chain{})
	rules, _ := document["rules"].([]any)
	if len(rules) == 0 || rules[len(rules)-1] != "MATCH,"+SelectGroup {
		t.Fatalf("traffic should still leave through the selection group: %v", rules)
	}
	proxies, _ := document["proxies"].([]any)
	if len(proxies) != 4 {
		t.Fatalf("nothing should have been added: %d proxies", len(proxies))
	}
}

// The exit reaches its own server through the selection group, so the group
// stays the first hop and Automatic keeps working without being resolved to a
// fixed node first.
func TestTheExitDialsThroughTheSelectionGroup(t *testing.T) {
	document := renderChain(t, Chain{ExitNode: "TCP Two"})

	proxies, _ := document["proxies"].([]any)
	var exit map[string]any
	for _, entry := range proxies {
		proxy, _ := entry.(map[string]any)
		if proxy["name"] == ChainExitName {
			exit = proxy
		}
	}
	if exit == nil {
		t.Fatalf("no exit proxy was rendered: %v", proxies)
	}
	if exit["dialer-proxy"] != SelectGroup {
		t.Fatalf("the exit does not dial through the first hop: %v", exit)
	}
	// It is a copy of the chosen node, so it must still describe that server.
	if exit["server"] != "b.example.com" || exit["type"] != "trojan" {
		t.Fatalf("the exit is not the node that was chosen: %v", exit)
	}

	rules, _ := document["rules"].([]any)
	if rules[len(rules)-1] != "MATCH,"+ChainExitName {
		t.Fatalf("traffic should leave through the exit: %v", rules)
	}
}

// The original stays in the config — the exit is a copy — but the first hop must
// not be able to choose it, or both ends of the chain would be one machine.
func TestTheFirstHopCannotChooseTheExitsServer(t *testing.T) {
	document := renderChain(t, Chain{ExitNode: "TCP Two"})
	for _, group := range []string{SelectGroup, AutoGroup} {
		for _, member := range groupMembers(t, document, group) {
			if member == "TCP Two" {
				t.Errorf("%s can still choose the exit's own node", group)
			}
		}
	}
	// And the others are still available to it.
	members := groupMembers(t, document, AutoGroup)
	if len(members) != 3 {
		t.Fatalf("the remaining nodes should all be first-hop candidates: %v", members)
	}
}

// A chain of a TCP-only first hop and a UDP exit builds, connects, and carries
// nothing. WireGuard and Hysteria2 move their payload in datagrams, so the hop
// beneath them has to be able to carry those.
func TestAUDPExitOnlyGetsFirstHopsThatCanCarryUDP(t *testing.T) {
	for _, exitNode := range []string{"Wire One", "UDP One"} {
		out, err := BuildProxiesYAMLWithChain(chainProxies(), SplitTunnel{}, Chain{ExitNode: exitNode})
		if err != nil {
			t.Fatalf("%s: %v", exitNode, err)
		}
		var document map[string]any
		if err := yaml.Unmarshal([]byte(out), &document); err != nil {
			t.Fatal(err)
		}
		for _, member := range groupMembers(t, document, AutoGroup) {
			if strings.HasPrefix(member, "TCP") {
				t.Errorf("%s needs UDP and %s cannot carry it", exitNode, member)
			}
		}
	}
}

// And when nothing can carry it, that is said rather than built.
func TestAUDPExitWithNoUDPCapableHopIsRefused(t *testing.T) {
	tcpOnly := []Proxy{
		{"name": "TCP One", "type": "vless", "server": "a.example.com", "port": 443},
		{"name": "Wire One", "type": "wireguard", "server": "d.example.com", "port": 51820, "udp": true},
	}
	_, err := BuildProxiesYAMLWithChain(tcpOnly, SplitTunnel{}, Chain{ExitNode: "Wire One"})
	if err == nil {
		t.Fatal("a chain that cannot carry its own traffic should be refused")
	}
	var chainErr *ChainError
	if !asChainError(err, &chainErr) {
		t.Fatalf("the interface has to be able to tell this from a build failure: %T", err)
	}
	if !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("the message should say what is wrong: %v", err)
	}
}

// A node chosen as the exit and then removed from the subscription.
func TestAnExitThatIsGoneIsReported(t *testing.T) {
	_, err := BuildProxiesYAMLWithChain(chainProxies(), SplitTunnel{}, Chain{ExitNode: "Not Here"})
	if err == nil {
		t.Fatal("choosing a node that no longer exists should be refused")
	}
	if !strings.Contains(err.Error(), "not in this subscription") {
		t.Fatalf("the message should say why: %v", err)
	}
}

// One node cannot be both ends of its own chain.
func TestASubscriptionOfOneCannotBeChained(t *testing.T) {
	one := []Proxy{{"name": "Only", "type": "vless", "server": "a.example.com", "port": 443}}
	_, err := BuildProxiesYAMLWithChain(one, SplitTunnel{}, Chain{ExitNode: "Only"})
	if err == nil {
		t.Fatal("a chain needs two nodes")
	}
}

func asChainError(err error, target **ChainError) bool {
	for err != nil {
		if chainErr, ok := err.(*ChainError); ok {
			*target = chainErr
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// A proxy that says it does not relay UDP cannot carry a datagram protocol,
// whatever its type. The claim is the proxy's own.
func TestAProxyThatDoesNotRelayUDPIsNotOfferedAsAUDPHop(t *testing.T) {
	proxies := []Proxy{
		{"name": "No UDP", "type": "wireguard", "server": "a.example.com", "port": 51820, "udp": false},
		{"name": "Wire One", "type": "wireguard", "server": "d.example.com", "port": 51820, "udp": true},
	}
	out, err := BuildProxiesYAMLWithChain(proxies, SplitTunnel{}, Chain{ExitNode: "Wire One"})
	if err == nil {
		t.Fatalf("the only other node cannot carry UDP, so this chain has no first hop:\n%s", out)
	}
}

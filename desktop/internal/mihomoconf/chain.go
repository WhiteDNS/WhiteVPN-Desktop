package mihomoconf

// Sending traffic through two nodes instead of one: device → node 1 → node 2 →
// internet, each node drawn from any subscription. The phone's
// ConnectionChainPlanner is the specification.
//
// mihomo's dialer-proxy is what makes this possible: a proxy carrying it is
// reached *through* the proxy it names, so naming node 1 on node 2 produces the
// chain. The name may be a group as well as a node, because the engine keeps
// groups in the same map it looks proxies up in — which is what lets node 1
// stay the ordinary selection group, so the session picks it, measures it and
// moves off a dead one exactly as it does without a chain.
//
// The shape, whatever the two modes:
//
//   - The selection group holds node 1's choices: every compatible config when
//     node 1 is Automatic, the one config when it is fixed.
//   - Node 2 is a copy of its config with dialer-proxy set to the selection
//     group, named ChainExitName. When node 2 is Automatic there is one copy per
//     candidate and ChainExitName is a url-test group over them.
//   - Traffic leaves through ChainExitName.
//
// Copies, because the original may also be one of node 1's choices, and one
// proxy cannot be both ends of the same chain. And every name is made unique
// across the two subscriptions, with a YAML subscription's own dialer-proxy
// chains renamed along with the proxies they name, so a node that already
// reaches its server through another of its subscription's proxies keeps doing
// so.
//
// Two things are not left to chance, as on the phone:
//
//   - Both ends cannot be one config, or two configs sharing one of their
//     inner proxies. The user would pay for two hops through one machine.
//   - When node 2 needs its dialer to carry UDP — WireGuard, Hysteria2, TUIC,
//     anything over QUIC — node 1 has to be able to. A chain assembled from a
//     TCP-only node 1 and a UDP node 2 builds, connects, and carries nothing.

import (
	"fmt"
	"slices"
	"strings"
)

// ChainExitName is what node 2 is called in the generated config.
//
// Fixed rather than derived from the node, so nothing downstream has to guess
// it, and visible enough that somebody reading a config knows why a proxy has a
// dialer-proxy on it.
const ChainExitName = "WhiteVPN Exit"

// ChainSource is one subscription's proxies, offered to a chain.
type ChainSource struct {
	ID      string
	Name    string
	Proxies []Proxy
}

// ChainRef names one config: its subscription and its name there.
type ChainRef struct {
	SubscriptionID string
	Node           string
}

// ChainHop is one node of a chain. A zero Ref is Automatic: the fastest
// working config from every source.
type ChainHop struct {
	Ref ChainRef
}

// Automatic reports whether this hop is chosen by the engine.
func (h ChainHop) Automatic() bool { return h.Ref.Node == "" }

// ChainIssue says why two configs cannot be node 1 and node 2 of one chain.
type ChainIssue string

const (
	// ChainIssueSame is one config at both ends.
	ChainIssueSame ChainIssue = "same"
	// ChainIssueShared is two configs of one subscription that reach their
	// servers through the same inner proxy.
	ChainIssueShared ChainIssue = "shared"
	// ChainIssueUDP is a node 2 that needs UDP over a node 1 that cannot carry it.
	ChainIssueUDP ChainIssue = "udp"
)

// Chain is a planned chain, as BuildProxiesYAMLWithRouting reads it.
//
// The proxies it names already carry their dialer-proxy wiring; see PlanChain.
// The zero value is no chain, the ordinary single-hop configuration.
type Chain struct {
	// Entries are node 1's choices: what the selection group holds.
	Entries []string
	// Exits are node 2's copies. One is named ChainExitName itself; several
	// are pooled in a url-test group of that name.
	Exits []string
}

// Active reports whether this chain does anything.
func (c Chain) Active() bool { return len(c.Exits) > 0 }

// ChainError explains why a chain could not be built.
//
// Its own type because every one of these is something a person chose and can
// choose differently, so the interface has to be able to say which.
type ChainError struct {
	Reason string
}

func (e *ChainError) Error() string { return e.Reason }

// chainCandidate is one config a hop could be.
type chainCandidate struct {
	ref    ChainRef
	source string
	// blocks is the config and every proxy it dials through inside its own
	// subscription, outermost dialer first and the config itself last.
	blocks []Proxy
}

func (c chainCandidate) entry() Proxy { return c.blocks[0] }
func (c chainCandidate) root() Proxy  { return c.blocks[len(c.blocks)-1] }

// chainCandidates is every config of a subscription that can be a hop.
func chainCandidates(source ChainSource) []chainCandidate {
	byName := make(map[string]Proxy, len(source.Proxies))
	for _, proxy := range source.Proxies {
		byName[proxy.Name()] = proxy
	}
	out := make([]chainCandidate, 0, len(source.Proxies))
	for _, proxy := range source.Proxies {
		if blocks := resolveProxyChain(proxy.Name(), byName); blocks != nil {
			out = append(out, chainCandidate{ref: ChainRef{source.ID, proxy.Name()}, source: source.Name, blocks: blocks})
		}
	}
	return out
}

func allChainCandidates(sources []ChainSource) []chainCandidate {
	var out []chainCandidate
	for _, source := range sources {
		out = append(out, chainCandidates(source)...)
	}
	return out
}

func findChainCandidate(candidates []chainCandidate, ref ChainRef) (chainCandidate, bool) {
	for _, candidate := range candidates {
		if candidate.ref == ref {
			return candidate, true
		}
	}
	return chainCandidate{}, false
}

// resolveProxyChain follows dialer-proxy inside one subscription.
//
// Nil when it names something that is not a proxy there — a group, usually,
// which is the provider's routing and not something a chain can carry across —
// when it loops, or when a hop inside it cannot carry the UDP the next needs.
func resolveProxyChain(name string, byName map[string]Proxy) []Proxy {
	var rootFirst []Proxy
	seen := map[string]bool{}
	for name != "" {
		proxy, ok := byName[name]
		if !ok || seen[name] {
			return nil
		}
		seen[name] = true
		rootFirst = append(rootFirst, proxy)
		name = strings.TrimSpace(stringField(proxy, "dialer-proxy"))
	}
	slices.Reverse(rootFirst)
	for i := 1; i < len(rootFirst); i++ {
		if requiresUDPDialer(rootFirst[i]) && !supportsUDPDialing(rootFirst[i-1]) {
			return nil
		}
	}
	return rootFirst
}

// ChainSelectable is the names of a subscription's configs that can be a hop.
func ChainSelectable(source ChainSource) map[string]bool {
	out := map[string]bool{}
	for _, candidate := range chainCandidates(source) {
		out[candidate.ref.Node] = true
	}
	return out
}

// chainPairIssue is why up cannot carry down, or empty when it can.
func chainPairIssue(up, down chainCandidate) ChainIssue {
	if issue := chainDistinctIssue(up, down); issue != "" {
		return issue
	}
	if requiresUDPDialer(down.entry()) && !supportsUDPDialing(up.root()) {
		return ChainIssueUDP
	}
	return ""
}

// chainDistinctIssue is the phone's distinctIssue. The phone compares content
// fingerprints; here a node is its name, so the same server listed by two
// providers is caught by its address and credential instead.
func chainDistinctIssue(first, second chainCandidate) ChainIssue {
	if first.ref == second.ref {
		return ChainIssueSame
	}
	if identity := identityOf(first.root()); identity != "" && identity == identityOf(second.root()) {
		return ChainIssueSame
	}
	if first.ref.SubscriptionID == second.ref.SubscriptionID {
		for _, a := range first.blocks {
			for _, b := range second.blocks {
				if a.Name() == b.Name() {
					return ChainIssueShared
				}
			}
		}
	}
	return ""
}

// ChainPickerIssues says why each config cannot fill one node next to the
// other node's fixed choice. Configs missing from the map are compatible, and
// an Automatic other node blocks nothing.
func ChainPickerIssues(sources []ChainSource, forEntry bool, other ChainHop) map[ChainRef]ChainIssue {
	if other.Automatic() {
		return nil
	}
	candidates := allChainCandidates(sources)
	fixed, ok := findChainCandidate(candidates, other.Ref)
	if !ok {
		return nil
	}
	issues := map[ChainRef]ChainIssue{}
	for _, candidate := range candidates {
		up, down := fixed, candidate
		if forEntry {
			up, down = candidate, fixed
		}
		issue := chainPairIssue(up, down)
		if issue != "" {
			issues[candidate.ref] = issue
		}
	}
	return issues
}

// PlanChain builds node 1 and node 2 out of the sources: the proxies the
// generated config needs, with their names made unique and their dialers
// wired, and the Chain that says which is which.
func PlanChain(sources []ChainSource, entry, exit ChainHop) ([]Proxy, Chain, error) {
	candidates := allChainCandidates(sources)
	pick := func(hop ChainHop, which string) ([]chainCandidate, error) {
		if hop.Automatic() {
			return candidates, nil
		}
		if candidate, ok := findChainCandidate(candidates, hop.Ref); ok {
			return []chainCandidate{candidate}, nil
		}
		return nil, &ChainError{Reason: fmt.Sprintf(
			"the config chosen as %s (%q) is not in its subscription any more, or dials through something a chain cannot carry — choose %s again", which, hop.Ref.Node, which)}
	}
	entries, err := pick(entry, "node 1")
	if err != nil {
		return nil, Chain{}, err
	}
	exits, err := pick(exit, "node 2")
	if err != nil {
		return nil, Chain{}, err
	}

	var issue ChainIssue
	switch {
	case !exit.Automatic():
		entries, issue = compatibleChainCandidates(entries, func(c chainCandidate) ChainIssue { return chainPairIssue(c, exits[0]) })
	case !entry.Automatic():
		exits, issue = compatibleChainCandidates(exits, func(c chainCandidate) ChainIssue { return chainPairIssue(entries[0], c) })
	default:
		// shortcut: with both nodes Automatic, node 1 is one group every node 2
		// dials through, so pairs cannot be ruled out one by one — only a node 2
		// needing UDP that the group may not carry. The two may land on one
		// server; give each node 2 its own node 1 group if that is reported.
		udp := !slices.ContainsFunc(entries, func(c chainCandidate) bool { return !supportsUDPDialing(c.root()) })
		exits, issue = compatibleChainCandidates(exits, func(c chainCandidate) ChainIssue {
			if requiresUDPDialer(c.entry()) && !udp {
				return ChainIssueUDP
			}
			return ""
		})
	}
	if len(entries) == 0 || len(exits) == 0 {
		return nil, Chain{}, chainIssueError(issue)
	}

	names := newNameRegistry()
	// Taken first, so a node that happens to share a name with one of the
	// app's own is the one renamed.
	for _, reserved := range []string{SelectGroup, AutoGroup, ChainExitName} {
		names.register(reserved)
	}
	merged := map[ChainRef]string{}
	nameOf := func(c chainCandidate, proxy Proxy) string {
		ref := ChainRef{c.ref.SubscriptionID, proxy.Name()}
		if name, ok := merged[ref]; ok {
			return name
		}
		name := names.register(qualify(proxy.Name(), c.source, names))
		merged[ref] = name
		return name
	}

	var out []Proxy
	written := map[string]bool{}
	emit := func(proxy Proxy, name, dialer string) {
		if written[name] {
			return
		}
		written[name] = true
		copied := make(Proxy, len(proxy)+1)
		for key, value := range proxy {
			copied[key] = value
		}
		copied["name"] = name
		delete(copied, "dialer-proxy")
		if dialer != "" {
			copied["dialer-proxy"] = dialer
		}
		out = append(out, copied)
	}

	var chain Chain
	for _, c := range entries {
		previous := ""
		for _, block := range c.blocks {
			name := nameOf(c, block)
			emit(block, name, previous)
			previous = name
		}
		chain.Entries = append(chain.Entries, previous)
	}
	for _, c := range exits {
		previous := SelectGroup
		for i, block := range c.blocks {
			name := ChainExitName + " · " + nameOf(c, block)
			if len(exits) == 1 && i == len(c.blocks)-1 {
				name = ChainExitName
			}
			emit(block, name, previous)
			previous = name
		}
		chain.Exits = append(chain.Exits, previous)
	}
	return out, chain, nil
}

// compatibleChainCandidates keeps the candidates with no issue, and returns
// one of the issues that ruled the rest out, for the error when none is left.
func compatibleChainCandidates(candidates []chainCandidate, issueOf func(chainCandidate) ChainIssue) ([]chainCandidate, ChainIssue) {
	kept := make([]chainCandidate, 0, len(candidates))
	var last ChainIssue
	for _, candidate := range candidates {
		if issue := issueOf(candidate); issue != "" {
			last = issue
			continue
		}
		kept = append(kept, candidate)
	}
	return kept, last
}

func chainIssueError(issue ChainIssue) error {
	switch issue {
	case ChainIssueSame:
		return &ChainError{Reason: "node 1 and node 2 are the same config — choose a different one for one of them"}
	case ChainIssueShared:
		return &ChainError{Reason: "node 1 and node 2 reach their servers through the same inner proxy — choose a config that does not share one"}
	case ChainIssueUDP:
		return &ChainError{Reason: "node 2 carries its traffic over UDP, and node 1 can only carry TCP — choose a node 1 that carries UDP, or a different node 2"}
	}
	return &ChainError{Reason: "there are no configs to build a chain from — refresh the subscriptions and try again"}
}

// requiresUDPDialer reports whether this proxy needs its dialer to carry UDP.
//
// The classification is the phone's MihomoProxyBlock.requiresUdpDialer, which
// took it from what mihomo can actually do: these move their payload in
// datagrams, so a hop beneath them that only carries streams has nothing to
// hand them to.
func requiresUDPDialer(proxy Proxy) bool {
	kind := proxyType(proxy)
	network := strings.ToLower(strings.TrimSpace(stringField(proxy, "network")))
	switch kind {
	case "openvpn":
		return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(stringField(proxy, "proto"))), "tcp")
	case "masque":
		return network != "h2"
	case "wireguard", "hysteria", "hysteria2", "hy2", "tuic", "juicity", "shadowquic":
		return true
	}
	switch network {
	case "quic", "h3", "kcp", "mkcp":
		return true
	}
	if strings.EqualFold(strings.TrimSpace(stringField(proxy, "transport")), "udp") {
		return true
	}
	// A native UDP relay asked to relay UDP needs its dialer to carry it,
	// unless it is tunnelling the datagrams over its own stream.
	switch kind {
	case "ss", "shadowsocks", "ssr", "shadowsocksr", "socks5", "gost-relay":
		return boolValue(proxy["udp"]) && !boolValue(proxy["udp-over-tcp"]) && !boolValue(proxy["udp-over-stream"])
	}
	return false
}

// supportsUDPDialing reports whether this proxy can carry UDP for another.
func supportsUDPDialing(proxy Proxy) bool {
	if proxy == nil {
		return false
	}
	if boolValue(proxy["udp"]) {
		return true
	}
	switch proxyType(proxy) {
	case "hysteria", "hysteria2", "hy2", "tuic", "shadowquic", "openvpn":
		return true
	}
	return false
}

func proxyType(proxy Proxy) string {
	return strings.ToLower(strings.TrimSpace(stringField(proxy, "type")))
}

func stringField(proxy Proxy, key string) string {
	value, _ := proxy[key].(string)
	return value
}

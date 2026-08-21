package mihomoconf

// Sending traffic through two nodes instead of one.
//
// mihomo's dialer-proxy is what makes this possible: a proxy carrying it is
// reached *through* the proxy it names, so naming the first hop on the second
// produces local → first → second → internet. The name may be a group as well
// as a node, because the engine keeps groups in the same map it looks proxies up
// in — which means the first hop can stay the ordinary selection group, and
// Automatic keeps working without being resolved to a fixed node first.
//
// The exit is rendered as a copy of the chosen node under a name of its own.
// A copy, because the original stays in the selection group where the first hop
// draws from, and one proxy cannot be both ends of the same chain.
//
// Two things are then not left to chance:
//
//   - The original is taken out of the first hop's choices. Otherwise the group
//     could pick the very server the exit is, and the user would pay for two
//     hops through one machine.
//   - When the exit needs its dialer to carry UDP — WireGuard, Hysteria2, TUIC,
//     anything over QUIC — the first hop's choices are narrowed to nodes that
//     can. A chain assembled from a TCP-only first hop and a UDP exit builds,
//     connects, and carries nothing.

import (
	"fmt"
	"strings"
)

// ChainExitName is what the second hop is called in the generated config.
//
// Fixed rather than derived from the node, so nothing downstream has to guess
// it, and visible enough that somebody reading a config knows why a proxy has a
// dialer-proxy on it.
const ChainExitName = "WhiteVPN Exit"

// Chain says whether traffic leaves through a second node, and which.
type Chain struct {
	// ExitNode is the name of the node traffic leaves from. Empty means no
	// chaining, which is the ordinary single-hop configuration.
	ExitNode string
}

// Active reports whether this chain does anything.
func (c Chain) Active() bool { return strings.TrimSpace(c.ExitNode) != "" }

// ChainError explains why a chain could not be built.
//
// Its own type because every one of these is something a person chose and can
// choose differently, so the interface has to be able to say which.
type ChainError struct {
	Reason string
}

func (e *ChainError) Error() string { return e.Reason }

// buildChain returns the exit proxy and the names the first hop may choose
// from, or an error naming what the user has to change.
func buildChain(proxies []Proxy, names []string, chain Chain) (Proxy, []string, error) {
	exitName := strings.TrimSpace(chain.ExitNode)

	var exit Proxy
	for _, proxy := range proxies {
		if proxy.Name() == exitName {
			exit = proxy
			break
		}
	}
	if exit == nil {
		return nil, nil, &ChainError{Reason: fmt.Sprintf(
			"the node chosen as the second hop is not in this subscription any more: %q", exitName)}
	}

	// The first hop draws from everything else. Taking the exit out is what
	// stops the group choosing the same server for both ends.
	first := make([]string, 0, len(names))
	for _, name := range names {
		if name != exitName {
			first = append(first, name)
		}
	}
	if len(first) == 0 {
		return nil, nil, &ChainError{Reason: "a chain needs a node for the first hop, and this subscription has only the one chosen as the second"}
	}

	if requiresUDPDialer(exit) {
		capable := make([]string, 0, len(first))
		byName := make(map[string]Proxy, len(proxies))
		for _, proxy := range proxies {
			byName[proxy.Name()] = proxy
		}
		for _, name := range first {
			if supportsUDPDialing(byName[name]) {
				capable = append(capable, name)
			}
		}
		if len(capable) == 0 {
			return nil, nil, &ChainError{Reason: fmt.Sprintf(
				"%q carries its traffic over UDP, and no other node in this subscription can carry UDP for it — choose a different second hop", exitName)}
		}
		first = capable
	}

	// A copy: the original stays where the first hop draws from.
	copied := make(Proxy, len(exit)+2)
	for key, value := range exit {
		copied[key] = value
	}
	copied["name"] = ChainExitName
	copied["dialer-proxy"] = SelectGroup
	return copied, first, nil
}

// requiresUDPDialer reports whether this proxy needs its dialer to carry UDP.
//
// The classification is the phone app's, which took it from what mihomo can
// actually do: these protocols move their payload in datagrams, so a first hop
// that only carries streams has nothing to hand them to.
func requiresUDPDialer(proxy Proxy) bool {
	switch proxyType(proxy) {
	case "wireguard", "hysteria", "hysteria2", "hy2", "tuic", "juicity", "shadowquic":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(stringField(proxy, "network"))) {
	case "quic", "h3", "kcp", "mkcp":
		return true
	}
	return false
}

// supportsUDPDialing reports whether this proxy can carry UDP for another.
func supportsUDPDialing(proxy Proxy) bool {
	if proxy == nil {
		return false
	}
	if enabled, ok := proxy["udp"].(bool); ok && enabled {
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

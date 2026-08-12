package mihomoconf

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Group names. The phone app names them and then finds them again by name —
// DNS resolution is routed through whichever group matches, and the connect flow
// selects nodes inside it — so these strings are part of the contract with the
// engine, not labels.
const (
	SelectGroup = "WhiteDNS Proxy"
	AutoGroup   = "WhiteDNS Auto"
)

// Defaults shared with WhiteVPN for Android. Changing one here without changing
// it there makes the two apps behave differently on the same subscription.
const (
	DefaultMixedPort   = 2080
	DefaultControlPort = 9090
	controllerHost     = "127.0.0.1"

	// DelayTestURL is what a delay measurement asks for, here and in the
	// url-test group, so the dialog and the engine agree on what "delay" means.
	DelayTestURL  = "https://connectivitycheck.gstatic.com/generate_204"
	autoInterval  = 300
	autoTolerance = 100

	DefaultDoHURL      = "https://1.1.1.1/dns-query"
	DefaultDoTEndpoint = "tls://1.1.1.1:853"
)

var (
	fallbackDoH = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}
	fallbackDoT = []string{"tls://1.1.1.1:853", "tls://8.8.8.8:853"}

	// The keys the runtime owns. Whatever a subscription says about these, the
	// app's values win, so they are removed before the overrides are appended —
	// leaving both would let the engine take either one.
	overrideKeys = map[string]bool{
		"port":                      true,
		"socks-port":                true,
		"mixed-port":                true,
		"redir-port":                true,
		"tproxy-port":               true,
		"listeners":                 true,
		"external-controller":       true,
		"external-controller-tls":   true,
		"external-controller-unix":  true,
		"external-controller-pipe":  true,
		"external-ui":               true,
		"external-ui-name":          true,
		"external-ui-url":           true,
		"external-doh-server":       true,
		"secret":                    true,
		"allow-lan":                 true,
		"bind-address":              true,
		"authentication":            true,
		"skip-auth-prefixes":        true,
		"lan-allowed-ips":           true,
		"lan-disallowed-ips":        true,
		"inbound-tfo":               true,
		"inbound-mptcp":             true,
		"mode":                      true,
		"log-level":                 true,
		"ipv6":                      true,
		"unified-delay":             true,
		"find-process-mode":         true,
		"global-client-fingerprint": true,
		"dns":                       true,
		"tun":                       true,
	}
)

// DNSPrivacyMode mirrors the phone's three-way setting.
type DNSPrivacyMode string

const (
	DNSAutomatic DNSPrivacyMode = "automatic"
	DNSOverHTTPS DNSPrivacyMode = "doh"
	DNSOverTLS   DNSPrivacyMode = "dot"
)

// TunOptions describes the tunnel interface.
//
// This is where the desktop deliberately parts company with the phone. Android
// sets tun.enable false and hands the engine a file descriptor from VpnService;
// the desktop build of the engine has no such entry point, so the tunnel has to
// come from configuration and mihomo creates the adapter itself.
type TunOptions struct {
	Enabled   bool
	Device    string
	MTU       int
	Stack     string
	AutoRoute bool

	// IPv6 decides whether v6 is carried through the tunnel or left alone.
	//
	// Leaving it alone is what Android does, and on Android that is safe: an
	// address family VpnService does not route simply cannot leave the device.
	// Windows has no such backstop — measured on a dual-stack machine, v4 goes
	// through the tunnel while v6 continues out of the physical adapter — so the
	// desktop carries v6 rather than ignoring it.
	IPv6 bool
	// Inet6Address gives the tunnel a v6 address so it can win the route. mihomo
	// does not remove the physical v6 default routes; it outranks them on metric,
	// which is why containment has to be verified after connecting and never
	// assumed.
	Inet6Address string

	// StrictRoute stops traffic finding its way around the tunnel, and it is what
	// closes the DNS leak the desktop had in tunnel mode.
	//
	// dns-hijack is not enough on its own, because it can only catch what enters
	// the tunnel. A resolver on the local network does not: the route to
	// 192.168.0.0/16 is directly connected on the physical adapter and beats the
	// 0.0.0.0/1 pair the tunnel installs, so every query to the home router left
	// the machine in the clear. That is why the leak showed in tunnel mode and not
	// in proxy mode — through a proxy the machine never resolves anything itself,
	// it hands over the name and mihomo does the lookup.
	//
	// The phone has no equivalent setting and does not need one: VpnService takes
	// DNS servers directly (`addDnsServer`), so Android routes every query into
	// the tunnel itself. Windows offers nothing like that. So this is the second
	// place, after IPv6 containment, where matching the phone literally would mean
	// shipping a leak.
	//
	// What it costs: on Windows, WFP filters that block port 53 for everything
	// except the engine and the tunnel adapter. On Linux, unreachable policy rules
	// to the same end. macOS ignores it. The Windows filters live in a session
	// opened with FWPM_SESSION_FLAG_DYNAMIC, so they are removed when the engine
	// exits — including when it is killed, which matters: filters that outlived a
	// crash would leave a machine unable to resolve anything until it rebooted.
	StrictRoute bool
}

// DefaultTunOptions are the desktop's tunnel settings, IPv6 contained.
func DefaultTunOptions() TunOptions {
	return TunOptions{
		Enabled:      true,
		Device:       "WhiteVPN",
		MTU:          9000,
		Stack:        "gvisor",
		AutoRoute:    true,
		IPv6:         true,
		Inet6Address: "fdfe:dcba:9876::1/126",
		StrictRoute:  true,
	}
}

// Options configures one runtime config.
type Options struct {
	MixedPort   int
	ControlPort int
	Secret      string

	// AllowLAN opens the local proxy to the rest of the network rather than to
	// this machine alone.
	//
	// It is what lets a phone on the same hotspot use this desktop's connection,
	// and it is also what lets anyone else on that network use it. Nothing
	// authenticates a client, so the only thing standing between the two is
	// whether the network is one the user trusts.
	AllowLAN bool

	DNSPrivacy  DNSPrivacyMode
	DoHURL      string
	DoTEndpoint string

	// ProxyGroup is the group DNS queries are resolved through. Empty means the
	// subscription has no group to route through, and respect-rules goes off with
	// it — pointing DNS at a group that does not exist would break resolution
	// entirely.
	ProxyGroup string

	Tun TunOptions

	// SplitTunnel decides whether the engine has to work out which program a
	// connection belongs to. It is here only so `find-process-mode` can follow
	// it; the rules themselves are built with the proxies.
	SplitTunnel SplitTunnel
}

// BuildProxiesYAML renders proxies plus the two default groups and a catch-all
// rule, which is what a link-based subscription needs: links carry nodes and
// nothing else, so without this there is nothing for traffic to match.
func BuildProxiesYAML(proxies []Proxy, split SplitTunnel) (string, error) {
	if len(proxies) == 0 {
		return "", fmt.Errorf("mihomoconf: no proxies to build a config from")
	}

	// Names are the engine's key for a proxy, so a duplicate silently replaces
	// rather than adds. The converter already suffixes them; this is the
	// backstop for proxies arriving from anywhere else.
	seen := make(map[string]bool, len(proxies))
	unique := make([]Proxy, 0, len(proxies))
	names := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		name := proxy.Name()
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		unique = append(unique, proxy)
		names = append(names, name)
	}
	if len(unique) == 0 {
		return "", fmt.Errorf("mihomoconf: no proxies with usable names")
	}

	document := map[string]any{
		"proxies": toNodes(unique),
		"proxy-groups": []any{
			map[string]any{
				"name":    SelectGroup,
				"type":    "select",
				"proxies": append([]string{AutoGroup}, names...),
			},
			map[string]any{
				"name":      AutoGroup,
				"type":      "url-test",
				"url":       DelayTestURL,
				"interval":  autoInterval,
				"tolerance": autoTolerance,
				"proxies":   names,
			},
		},
		// Split-tunnel rules first, because mihomo takes the first rule that
		// fits: a catch-all above them means nothing below is ever reached.
		"rules": append(split.Rules(SelectGroup), catchAllRules(split)...),
	}

	encoded, err := yaml.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// catchAllRules is what everything not matched already does.
//
// Empty when the split tunnel has written its own catch-all, because two would
// mean the second is dead — and the dead one would be the one saying everything
// goes through the tunnel, which is exactly the line someone reading the config
// to answer "why is this not tunnelled" would stop at.
func catchAllRules(split SplitTunnel) []string {
	if split.Catches() {
		return nil
	}
	return []string{"MATCH," + SelectGroup}
}

// toNodes puts the identifying fields first so a config is readable when someone
// has to inspect one, and leaves the rest in a stable order so two runs over the
// same subscription produce the same file.
func toNodes(proxies []Proxy) []any {
	leading := []string{"name", "type", "server", "port"}
	isLeading := map[string]bool{"name": true, "type": true, "server": true, "port": true}

	nodes := make([]any, 0, len(proxies))
	for _, proxy := range proxies {
		order := make([]string, 0, len(proxy))
		for _, key := range leading {
			if _, present := proxy[key]; present {
				order = append(order, key)
			}
		}
		rest := make([]string, 0, len(proxy))
		for key := range proxy {
			if !isLeading[key] {
				rest = append(rest, key)
			}
		}
		sort.Strings(rest)
		nodes = append(nodes, orderedMapping(append(order, rest...), proxy))
	}
	return nodes
}

// orderedMapping builds a YAML mapping that keeps the given key order. yaml.v3
// sorts a Go map's keys, which is stable but puts a proxy's name somewhere in
// the middle of its options — unhelpful when reading a config to diagnose one.
func orderedMapping(order []string, values map[string]any) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode}
	for _, key := range order {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
		valueNode := &yaml.Node{}
		if err := valueNode.Encode(values[key]); err != nil {
			continue
		}
		node.Content = append(node.Content, keyNode, valueNode)
	}
	return node
}

// Render produces the config the engine reads, by stripping the keys the runtime
// owns from the subscription and appending the app's own values.
func Render(subscriptionYAML string, opts Options) string {
	opts = withDefaults(opts)

	var out strings.Builder
	if stripped := StripTopLevelKeys(subscriptionYAML, overrideKeys); strings.TrimSpace(stripped) != "" {
		out.WriteString(strings.TrimRight(stripped, "\n"))
		out.WriteString("\n\n")
	}

	suffix := ""
	if opts.ProxyGroup != "" {
		// Resolving through the proxy group rather than directly is what stops
		// DNS from revealing which names are being looked up.
		suffix = "#" + opts.ProxyGroup
	}

	out.WriteString("# WhiteVPN Desktop runtime overrides\n")
	fmt.Fprintf(&out, "mixed-port: %d\n", opts.MixedPort)
	fmt.Fprintf(&out, "external-controller: %s:%d\n", controllerHost, opts.ControlPort)
	fmt.Fprintf(&out, "secret: %s\n", quoteYAML(opts.Secret))
	fmt.Fprintf(&out, "allow-lan: %t\n", opts.AllowLAN)
	if opts.AllowLAN {
		// Said explicitly rather than left to the engine's default for it, so
		// that what the listener binds is decided here and stays decided.
		out.WriteString("bind-address: \"*\"\n")
	}
	out.WriteString("mode: rule\n")
	out.WriteString("log-level: warning\n")
	fmt.Fprintf(&out, "ipv6: %t\n", opts.Tun.IPv6)
	out.WriteString("unified-delay: true\n")
	// Which program a connection belongs to costs a lookup per connection, so it
	// is only asked for when a rule needs the answer. `strict` is mihomo's own
	// default and means exactly that; `off` stops it entirely, which is worth
	// saying rather than leaving to the default in case that default moves.
	if opts.SplitTunnel.Active() {
		out.WriteString("find-process-mode: strict\n")
	} else {
		out.WriteString("find-process-mode: off\n")
	}
	// global-client-fingerprint is deliberately not written. mihomo removed it,
	// and this engine logs an error and ignores it. Nothing is lost: the
	// converter already sets client-fingerprint on every proxy that carries TLS,
	// which is the only kind the setting ever applied to.

	out.WriteString("dns:\n")
	out.WriteString("  enable: true\n")
	out.WriteString("  listen: 127.0.0.1:1053\n")
	fmt.Fprintf(&out, "  ipv6: %t\n", opts.Tun.IPv6)
	fmt.Fprintf(&out, "  respect-rules: %t\n", opts.ProxyGroup != "")
	out.WriteString("  enhanced-mode: fake-ip\n")
	out.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	out.WriteString("  default-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n")
	out.WriteString("  nameserver:\n")
	for _, server := range nameservers(opts) {
		fmt.Fprintf(&out, "    - %s\n", quoteYAML(server+suffix))
	}
	out.WriteString("  proxy-server-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n")

	out.WriteString(renderTun(opts.Tun))
	return out.String()
}

func renderTun(tun TunOptions) string {
	if !tun.Enabled {
		return "tun:\n  enable: false\n"
	}
	var out strings.Builder
	out.WriteString("tun:\n")
	out.WriteString("  enable: true\n")
	fmt.Fprintf(&out, "  device: %s\n", quoteYAML(tun.Device))
	fmt.Fprintf(&out, "  stack: %s\n", tun.Stack)
	fmt.Fprintf(&out, "  mtu: %d\n", tun.MTU)
	fmt.Fprintf(&out, "  auto-route: %t\n", tun.AutoRoute)
	out.WriteString("  auto-detect-interface: true\n")
	// Without hijacking port 53 a program that talks to a hard-coded resolver
	// bypasses the tunnel's DNS entirely, which both leaks the query and defeats
	// fake-ip.
	out.WriteString("  dns-hijack:\n    - any:53\n")
	// And hijacking is only half of it: it catches what enters the tunnel, and a
	// query to the router on the local network never does. See StrictRoute.
	fmt.Fprintf(&out, "  strict-route: %t\n", tun.StrictRoute)
	if tun.IPv6 && tun.Inet6Address != "" {
		fmt.Fprintf(&out, "  inet6-address:\n    - %s\n", tun.Inet6Address)
	}
	return out.String()
}

func nameservers(opts Options) []string {
	switch opts.DNSPrivacy {
	case DNSOverHTTPS:
		return dedupe(append([]string{opts.DoHURL}, fallbackDoH...))
	case DNSOverTLS:
		return dedupe(append([]string{opts.DoTEndpoint}, fallbackDoT...))
	default:
		return append(append([]string{}, fallbackDoH...), fallbackDoT...)
	}
}

func withDefaults(opts Options) Options {
	if opts.MixedPort == 0 {
		opts.MixedPort = DefaultMixedPort
	}
	if opts.ControlPort == 0 {
		opts.ControlPort = DefaultControlPort
	}
	if opts.DNSPrivacy == "" {
		opts.DNSPrivacy = DNSAutomatic
	}
	if strings.TrimSpace(opts.DoHURL) == "" {
		opts.DoHURL = DefaultDoHURL
	}
	if strings.TrimSpace(opts.DoTEndpoint) == "" {
		opts.DoTEndpoint = DefaultDoTEndpoint
	}
	if opts.Tun.Enabled && opts.Tun.Stack == "" {
		opts.Tun.Stack = "gvisor"
	}
	if opts.Tun.Enabled && opts.Tun.MTU == 0 {
		opts.Tun.MTU = 9000
	}
	if opts.Tun.Enabled && opts.Tun.Device == "" {
		opts.Tun.Device = "WhiteVPN"
	}
	return opts
}

// StripTopLevelKeys removes a top-level key and everything nested beneath it.
//
// It works line by line rather than through a YAML round trip on purpose: a
// subscription is whatever the provider sent, and re-emitting it would rewrite
// parts nobody asked to change and lose comments and ordering along the way.
func StripTopLevelKeys(document string, keys map[string]bool) string {
	normalised := strings.ReplaceAll(strings.ReplaceAll(document, "\r\n", "\n"), "\r", "\n")
	var kept []string
	skipping := false

	for _, line := range strings.Split(normalised, "\n") {
		key := topLevelKey(line)
		if skipping {
			// A stripped key's block ends at the next top-level line; blank lines
			// and indented ones still belong to it.
			atBoundary := key != "" || (strings.TrimSpace(line) != "" && !startsWithSpace(line))
			if !atBoundary {
				continue
			}
			skipping = false
		}
		if key != "" && keys[key] {
			skipping = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n \t")
}

func topLevelKey(line string) string {
	if strings.TrimSpace(line) == "" || startsWithSpace(line) || strings.HasPrefix(strings.TrimSpace(line), "#") {
		return ""
	}
	index := strings.Index(line, ":")
	if index <= 0 {
		return ""
	}
	return strings.TrimSpace(line[:index])
}

func startsWithSpace(line string) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}

func quoteYAML(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

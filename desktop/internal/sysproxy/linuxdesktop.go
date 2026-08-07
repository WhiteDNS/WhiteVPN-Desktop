package sysproxy

import (
	"fmt"
	"strconv"
	"strings"
)

// Names the Linux backends are addressed by. They live in this file rather than
// beside the code that runs the commands so both are reachable from a test on
// any platform — this is developed on Windows and built for Linux, and a
// constant behind a build tag would take the argument-building with it.
const (
	gsettingsBinary    = "gsettings"
	gnomeProxySchema   = "org.gnome.system.proxy"
	kdeProxyConfigFile = "kioslaverc"
	kdeProxyGroup      = "Proxy Settings"
)

// splitEndpoint separates "host:port". Shared with the Linux backends, and kept
// here rather than beside them so the tests can reach it from any platform.
func splitProxyEndpoint(endpoint string) (string, int) {
	host, portText, found := strings.Cut(strings.TrimSpace(endpoint), ":")
	if !found {
		return "", 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0
	}
	return host, port
}

// The parts of the Linux backends that are just text: what to write, and how to
// read back what was written.
//
// Separated from the code that runs the commands so it can be tested anywhere,
// rather than only on a machine with GNOME or KDE in front of it. The commands
// themselves cannot be checked without that machine; the arguments they are
// given can.

// gnomeApplyArgs is the sequence of `gsettings` calls that puts state in place.
//
// The host and port go in even when the proxy is being turned off. Leaving them
// behind is how the desktop's own settings dialog behaves, and it means turning
// the proxy back on does not need them written again — but more to the point,
// clearing them on disconnect would wipe a proxy the user had configured
// themselves before this app ever ran.
func gnomeApplyArgs(state State) [][]string {
	if !state.Enabled {
		return [][]string{{"set", gnomeProxySchema, "mode", "none"}}
	}

	host, port := splitProxyEndpoint(state.Server)
	portText := strconv.Itoa(port)
	args := [][]string{
		{"set", gnomeProxySchema, "mode", "manual"},
	}
	// http and https both, because a browser sends CONNECT for https to
	// whatever the https entry names and would go direct if it were empty.
	// socks as well: it is the same mixed port, and a program that prefers
	// socks should not fall out of the tunnel for choosing it.
	for _, child := range []string{"http", "https", "socks"} {
		args = append(args,
			[]string{"set", gnomeProxySchema + "." + child, "host", host},
			[]string{"set", gnomeProxySchema + "." + child, "port", portText},
		)
	}
	args = append(args, []string{"set", gnomeProxySchema, "ignore-hosts", gnomeIgnoreHosts(state.Override)})
	return args
}

// gnomeIgnoreHosts turns the semicolon-separated bypass list into the GVariant
// array literal gsettings expects.
func gnomeIgnoreHosts(override string) string {
	entries := bypassEntries(override)
	quoted := make([]string, 0, len(entries))
	for _, entry := range entries {
		quoted = append(quoted, "'"+strings.ReplaceAll(entry, "'", "")+"'")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// parseGnomeState reads back what gsettings reports. Values arrive quoted.
func parseGnomeState(mode, host, port, ignore string) State {
	state := State{Enabled: strings.Trim(strings.TrimSpace(mode), "'\"") == "manual"}
	host = strings.Trim(strings.TrimSpace(host), "'\"")
	portNumber, err := strconv.Atoi(strings.TrimSpace(port))
	if host != "" && err == nil && portNumber > 0 {
		state.Server = fmt.Sprintf("%s:%d", host, portNumber)
	}
	state.Override = strings.Join(parseGnomeIgnoreHosts(ignore), ";")
	return state
}

func parseGnomeIgnoreHosts(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "@as ")
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if strings.TrimSpace(value) == "" {
		return nil
	}
	entries := make([]string, 0, 8)
	for _, field := range strings.Split(value, ",") {
		field = strings.Trim(strings.TrimSpace(field), "'\"")
		if field != "" {
			entries = append(entries, field)
		}
	}
	return entries
}

// kdeApplyEntries is the kioslaverc keys that put state in place.
//
// ProxyType 1 is manual and 0 is none, which is KDE's own numbering. The proxy
// values are written as URLs; KDE has accepted that form for years and it
// avoids the older "host port" shape, which is easy to get subtly wrong.
func kdeApplyEntries(state State) map[string]string {
	if !state.Enabled {
		return map[string]string{"ProxyType": "0"}
	}
	host, port := splitProxyEndpoint(state.Server)
	endpoint := fmt.Sprintf("%s:%d", host, port)
	return map[string]string{
		"ProxyType":         "1",
		"httpProxy":         "http://" + endpoint,
		"httpsProxy":        "http://" + endpoint,
		"socksProxy":        "socks://" + endpoint,
		"NoProxyFor":        strings.Join(bypassEntries(state.Override), ","),
		"ReversedException": "false",
	}
}

func parseKDEState(proxyType, httpProxy, noProxyFor string) State {
	state := State{Enabled: strings.TrimSpace(proxyType) == "1"}
	if endpoint := stripProxyScheme(httpProxy); endpoint != "" {
		state.Server = endpoint
	}
	entries := make([]string, 0, 8)
	for _, field := range strings.Split(noProxyFor, ",") {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	state.Override = strings.Join(entries, ";")
	return state
}

func stripProxyScheme(value string) string {
	value = strings.TrimSpace(value)
	for _, scheme := range []string{"http://", "https://", "socks://", "socks5://"} {
		value = strings.TrimPrefix(value, scheme)
	}
	// The older KDE form separates host and port with a space.
	value = strings.TrimSpace(value)
	if host, port, found := strings.Cut(value, " "); found {
		value = host + ":" + strings.TrimSpace(port)
	}
	if value == "" || strings.HasSuffix(value, ":") {
		return ""
	}
	return value
}

// bypassEntries splits the Windows-shaped bypass list into what the Linux
// desktops want.
//
// `<local>` is dropped: it is WinINET's word for "any name without a dot" and
// means nothing to GNOME or KDE, which would take it literally and try to match
// a host called "<local>".
func bypassEntries(override string) []string {
	entries := make([]string, 0, 24)
	for _, field := range strings.Split(override, ";") {
		field = strings.TrimSpace(field)
		if field == "" || strings.EqualFold(field, "<local>") {
			continue
		}
		entries = append(entries, field)
	}
	return entries
}

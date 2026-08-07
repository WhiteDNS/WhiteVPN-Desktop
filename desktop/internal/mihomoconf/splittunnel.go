package mihomoconf

import (
	"fmt"
	"strings"
)

// Routing some programs around the tunnel, or only some through it.
//
// The setting existed for a while and did nothing. It was stored, validated and
// shown, and no code outside the model ever read it — a user could add a program
// to the bypass list, save, and watch the site it was meant to reach still see
// the VPN's address, because every byte still went through the tunnel. That is
// the same shape as IP fronting before it was wired: a control that changes
// nothing is worse than one that is missing, because the missing one does not
// lie about it.
//
// mihomo does this with `PROCESS-NAME` rules, matched ahead of the catch-all.
// The rules go before MATCH because mihomo takes the first that fits, so a
// catch-all above them would mean nothing below is ever reached.

// SplitTunnelMode is which way the exception runs.
type SplitTunnelMode string

const (
	// SplitTunnelOff sends everything through the tunnel.
	SplitTunnelOff SplitTunnelMode = ""
	// SplitTunnelBypass sends the named programs around it.
	SplitTunnelBypass SplitTunnelMode = "bypass"
	// SplitTunnelOnly sends only the named programs through it.
	SplitTunnelOnly SplitTunnelMode = "only"
)

// SplitTunnel names the programs and which way the exception runs.
type SplitTunnel struct {
	Mode SplitTunnelMode
	// Processes are executable names as the operating system reports them —
	// `chrome.exe` on Windows, `firefox` elsewhere. Matching is on the name
	// alone, so two programs installed under the same one cannot be told apart.
	Processes []string
}

// Rules returns the rule lines this split tunnel needs, in order, without the
// catch-all that follows them.
//
// An empty result means every rule is the catch-all's: either the feature is
// off, or it names nothing, and naming nothing must not change the routing. The
// vpn-only mode with an empty list is the dangerous case — read literally it
// says "send nothing through the tunnel", which would silently turn the VPN off
// while the interface still said Connected — so it is treated as off, which is
// what the model already does when it normalises.
func (s SplitTunnel) Rules(group string) []string {
	names := cleanProcessNames(s.Processes)
	if len(names) == 0 || group == "" {
		return nil
	}

	switch s.Mode {
	case SplitTunnelBypass:
		rules := make([]string, 0, len(names))
		for _, name := range names {
			rules = append(rules, fmt.Sprintf("PROCESS-NAME,%s,DIRECT", name))
		}
		return rules
	case SplitTunnelOnly:
		rules := make([]string, 0, len(names)+1)
		for _, name := range names {
			rules = append(rules, fmt.Sprintf("PROCESS-NAME,%s,%s", name, group))
		}
		// Everything else goes direct. This is the rule that makes the mode mean
		// what it says, and it replaces the catch-all rather than joining it.
		rules = append(rules, "MATCH,DIRECT")
		return rules
	default:
		return nil
	}
}

// Catches reports whether these rules already end in a catch-all, so the caller
// knows not to add another after them.
func (s SplitTunnel) Catches() bool {
	return s.Mode == SplitTunnelOnly && len(cleanProcessNames(s.Processes)) > 0
}

// Active reports whether the split tunnel changes any routing, which is what
// decides whether the engine has to look processes up at all.
func (s SplitTunnel) Active() bool {
	return len(s.Rules(SelectGroup)) > 0
}

// cleanProcessNames trims, drops blanks, and removes duplicates while keeping
// the order the user put them in.
//
// A rule naming an empty process matches nothing and is worth removing rather
// than writing: mihomo accepts it, and a config full of rules that cannot fire
// is a config nobody can read when something goes wrong.
func cleanProcessNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	names := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" {
			continue
		}
		// A rule is one line: a name with a comma in it would be read as extra
		// fields and change what the rule means.
		if strings.ContainsAny(name, ",\n\r") {
			continue
		}
		key := strings.ToLower(name)
		if _, taken := seen[key]; taken {
			continue
		}
		seen[key] = struct{}{}
		names = append(names, name)
	}
	return names
}

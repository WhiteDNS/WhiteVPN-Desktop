package mihomoconf

import "strings"

// Padding a WireGuard connection with junk so its shape is less recognisable.
//
// This is the phone's WARP/Amnezia noise setting, and like split tunnelling and
// IP fronting before it, the desktop stored it, validated it, showed it, and
// never read it — three numeric fields and a switch that changed nothing.
//
// It applies to WireGuard and nothing else. That is not a shortcut: the noise is
// AmneziaWG's, implemented in the WireGuard outbound, and mihomo has nowhere to
// put it on a vless or trojan proxy. Android draws the same line —
//
//	amneziaNoise = if (options.amneziaNoiseEnabled && profile.type.equals("wireguard", true))
//
// — so a subscription with no WireGuard nodes is one where this setting still
// changes nothing, correctly. The interface has to say that rather than let
// someone turn it on and wonder.

// AmneziaNoise is how much junk to pad a WireGuard handshake with.
//
// The three numbers are mihomo's jc, jmin and jmax: how many junk packets, and
// the smallest and largest each may be.
type AmneziaNoise struct {
	Enabled bool
	Count   int
	MinSize int
	MaxSize int
}

// usable reports whether this would change anything if applied.
//
// A count of zero is off however the switch is set — mihomo would take it as "no
// junk packets", which is what not enabling it means anyway, and writing the
// option to say nothing only makes the config harder to read.
func (n AmneziaNoise) usable() bool {
	return n.Enabled && n.Count > 0 && n.MinSize > 0 && n.MaxSize >= n.MinSize
}

// ApplyAmneziaNoise pads every WireGuard proxy in the list, and reports how many
// it reached.
//
// The count is worth having rather than discarding: a user who turned this on
// against a catalogue of vless nodes has changed nothing, and the only way to
// tell them so is to know.
func ApplyAmneziaNoise(proxies []Proxy, noise AmneziaNoise) ([]Proxy, int) {
	if !noise.usable() {
		return proxies, 0
	}

	out := make([]Proxy, 0, len(proxies))
	changed := 0
	for _, proxy := range proxies {
		if !isWireGuard(proxy) {
			out = append(out, proxy)
			continue
		}
		// Copied rather than written through: the caller's slice holds the
		// proxies parsed from the subscription, and a setting should not edit
		// what the subscription said.
		next := make(Proxy, len(proxy)+1)
		for key, value := range proxy {
			next[key] = value
		}
		next["amnezia-wg-option"] = map[string]any{
			"jc":   noise.Count,
			"jmin": noise.MinSize,
			"jmax": noise.MaxSize,
		}
		out = append(out, next)
		changed++
	}
	return out, changed
}

func isWireGuard(proxy Proxy) bool {
	value, _ := proxy["type"].(string)
	return strings.EqualFold(strings.TrimSpace(value), "wireguard")
}

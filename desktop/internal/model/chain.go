package model

import "strings"

// The connection chain: device → node 1 → node 2 → internet, with each node
// drawn from any subscription. It is the phone's ConnectionChainSettings with
// the Base and After slots, named for what they do here — node 1 is where the
// traffic enters, node 2 is where it leaves.

// Hop modes, matching the phone's ConnectionChainHopMode wire names.
const (
	ChainHopOff       = "off"
	ChainHopAutomatic = "automatic"
	ChainHopFixed     = "fixed"
)

// ChainHop is one node of the chain.
//
// A fixed hop names its config by subscription and node name. The name rather
// than a position, because a refresh reorders the list and a position would
// quietly come to mean a different server.
type ChainHop struct {
	Mode           string `json:"mode"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	Node           string `json:"node,omitempty"`
}

// ChainSettings is the two nodes.
type ChainSettings struct {
	// Entry is node 1. It is never off: with no node 2 it does nothing, and
	// with one it is what node 2 is reached through.
	Entry ChainHop `json:"entry"`
	// Exit is node 2. Off is "No node 2", the ordinary single-hop connection.
	Exit ChainHop `json:"exit"`
}

// Active reports whether traffic goes through two nodes.
func (c ChainSettings) Active() bool { return c.Exit.Mode != ChainHopOff }

// DefaultChainSettings is no chain, with node 1 ready as Automatic.
func DefaultChainSettings() ChainSettings {
	return ChainSettings{Entry: ChainHop{Mode: ChainHopAutomatic}, Exit: ChainHop{Mode: ChainHopOff}}
}

// NormalizeChainSettings repairs a chain read from disk or sent by the
// interface, the way the phone's normalized() does: node 1 cannot be off, and
// a fixed node missing either half of its reference falls back to what the
// slot means when nothing is chosen.
func NormalizeChainSettings(chain ChainSettings) ChainSettings {
	chain.Entry = normalizeChainHop(chain.Entry, ChainHopAutomatic)
	chain.Exit = normalizeChainHop(chain.Exit, ChainHopOff)
	return chain
}

func normalizeChainHop(hop ChainHop, unset string) ChainHop {
	hop.SubscriptionID = strings.TrimSpace(hop.SubscriptionID)
	hop.Node = strings.TrimSpace(hop.Node)
	switch hop.Mode {
	case ChainHopFixed:
		if hop.SubscriptionID != "" && hop.Node != "" {
			return hop
		}
	case ChainHopAutomatic:
		// A list id narrows Automatic to that list; no id means every list.
		return ChainHop{Mode: ChainHopAutomatic, SubscriptionID: hop.SubscriptionID}
	}
	return ChainHop{Mode: unset}
}

// MigrateLegacyChain carries a chain set up before nodes could come from two
// subscriptions into the two-node model.
//
// That chain was an exit name in the selected subscription, reached through
// whatever the VPN page connected to: its pinned node, or Automatic. So the
// exit becomes a fixed node 2 in that subscription, and a pinned node becomes a
// fixed node 1; an unpinned one stays Automatic, which now looks across every
// subscription rather than one.
func MigrateLegacyChain(settings WhiteVPNSettings, selectedSubscriptionID string) WhiteVPNSettings {
	exit := strings.TrimSpace(settings.ChainExitNode)
	settings.ChainExitNode = ""
	if exit == "" || NormalizeChainSettings(settings.Chain).Active() {
		return settings
	}
	subscription := strings.TrimSpace(selectedSubscriptionID)
	if subscription == "" {
		subscription = BuiltInSubscriptionID
	}
	settings.Chain = ChainSettings{
		Entry: ChainHop{Mode: ChainHopAutomatic},
		Exit:  ChainHop{Mode: ChainHopFixed, SubscriptionID: subscription, Node: exit},
	}
	if node := strings.TrimSpace(settings.Connection.Node); node != "" {
		settings.Chain.Entry = ChainHop{Mode: ChainHopFixed, SubscriptionID: subscription, Node: node}
	}
	return settings
}

// Chain picker slots, as the interface names them.
const (
	ChainSlotEntry = "entry"
	ChainSlotExit  = "exit"
)

// ChainOptionGroup is one subscription's configs in the chain picker.
type ChainOptionGroup struct {
	SubscriptionID string `json:"subscriptionId"`
	Name           string `json:"name"`
	// UserMade is every list that is not a built-in catalogue — WARP, a
	// provider somebody added, their own saved configs. The picker shows these
	// first.
	UserMade bool           `json:"userMade"`
	Nodes    []WhiteVPNNode `json:"nodes"`
	// Issues says, by node name, why a config cannot fill this slot next to
	// the other node's fixed choice: "same", "shared" or "udp".
	Issues map[string]string `json:"issues,omitempty"`
}

// ChainOptions is everything the chain picker lists.
type ChainOptions struct {
	Groups []ChainOptionGroup `json:"groups"`
	// Incomplete means at least one subscription could not be read, so the
	// list is missing configs it should have.
	Incomplete bool `json:"incomplete"`
}

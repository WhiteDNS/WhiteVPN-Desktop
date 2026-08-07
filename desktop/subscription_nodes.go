package main

// What a user can do to a node that is not theirs.
//
// A subscription's nodes belong to whoever serves them. Refreshing one drops
// every profile it produced and re-imports from the remote body with fresh ids
// built from a timestamp, so editing a subscription node is not a feature that
// could be built badly — it is a feature that cannot exist. Whatever was changed
// is gone at the next refresh, and there is not even a stable id to hang the
// change on. Subscriptions served as a mihomo document produce no profiles at
// all; their nodes are read straight out of the body.
//
// So instead of pretending, two things that are true:
//
// Copy takes the node out of the subscription and into the user's own configs,
// where it is theirs and the edit form already works. It needs the node's share
// link, which a document-shaped subscription does not carry — the same
// limitation the Share button already has, and shown the same way.
//
// Hide takes a node out of the list and out of the engine's configuration
// without claiming to have deleted anything, and survives a refresh because it
// is held by name rather than by an id that will not exist tomorrow.

import (
	"fmt"
	"slices"
	"strings"

	"whitevpn-desktop/internal/model"
)

// CopyNodeToManual adds a subscription's node to the user's own configs.
func (a *App) CopyNodeToManual(subscriptionID string, nodeName string) (model.V2RayImportResult, error) {
	subscriptionID = strings.TrimSpace(subscriptionID)
	nodeName = strings.TrimSpace(nodeName)
	if subscriptionID == "" || nodeName == "" {
		return model.V2RayImportResult{State: a.GetAppState()}, fmt.Errorf("no node to copy")
	}

	var link string
	for _, node := range a.whiteVPNNodesSnapshot(subscriptionID) {
		if node.Name == nodeName {
			link = strings.TrimSpace(node.Link)
			break
		}
	}
	if link == "" {
		// Either the node is gone, or it came from a configuration document and
		// has no link. Both leave nothing to copy, and the second is worth saying
		// plainly rather than reporting as a missing node.
		return model.V2RayImportResult{State: a.GetAppState()},
			fmt.Errorf("this node came from a configuration file, so there is no link to copy")
	}

	// Through the ordinary import, so a copied node is parsed by exactly the same
	// code as one pasted in by hand and cannot end up in a shape nothing else
	// produces.
	result, err := a.ImportV2RayProfiles(link)
	if err != nil {
		return result, err
	}
	a.forgetWhiteVPNNodes(model.ManualServerSourceID)
	return result, nil
}

// SetNodesHidden takes nodes out of a subscription, or puts them back.
func (a *App) SetNodesHidden(subscriptionID string, nodeNames []string, hidden bool) (model.WhiteVPNNodeList, error) {
	subscriptionID = strings.TrimSpace(subscriptionID)
	if subscriptionID == "" {
		return a.snapshotWhiteVPNNodes(subscriptionID), fmt.Errorf("no subscription named")
	}
	wanted := make([]string, 0, len(nodeNames))
	for _, name := range nodeNames {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			wanted = append(wanted, trimmed)
		}
	}
	if len(wanted) == 0 {
		return a.snapshotWhiteVPNNodes(subscriptionID), nil
	}

	if hidden {
		// Hiding everything would leave the engine nothing to build a
		// configuration from, and the failure would arrive later as an error about
		// a missing group. Refusing here says what actually happened.
		if remaining := a.visibleNodeCount(subscriptionID, wanted); remaining == 0 {
			return a.snapshotWhiteVPNNodes(subscriptionID),
				fmt.Errorf("that would hide every node in this subscription; leave at least one")
		}
	}

	a.mu.Lock()
	if a.state.HiddenNodes == nil {
		a.state.HiddenNodes = map[string][]string{}
	}
	current := append([]string(nil), a.state.HiddenNodes[subscriptionID]...)
	for _, name := range wanted {
		if hidden {
			if !slices.Contains(current, name) {
				current = append(current, name)
			}
			continue
		}
		current = slices.DeleteFunc(current, func(existing string) bool { return existing == name })
	}
	a.state.HiddenNodes[subscriptionID] = current
	_, err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		return a.snapshotWhiteVPNNodes(subscriptionID), err
	}

	// The flags live on the cached list, so they are updated in place. Dropping
	// the cache instead would send this local change back to the network for a
	// list it already has, and would fail outright with no connection.
	return a.reapplyHiddenNodes(subscriptionID), nil
}

// reapplyHiddenNodes brings the cached list's flags back in line with what is
// stored, and hands the list back.
func (a *App) reapplyHiddenNodes(subscriptionID string) model.WhiteVPNNodeList {
	hidden := a.hiddenNodeNames(subscriptionID)
	lookup := make(map[string]struct{}, len(hidden))
	for _, name := range hidden {
		lookup[name] = struct{}{}
	}

	a.nodesMu.Lock()
	defer a.nodesMu.Unlock()
	for i := range a.nodes[subscriptionID] {
		_, a.nodes[subscriptionID][i].Hidden = lookup[a.nodes[subscriptionID][i].Name]
	}
	return a.nodeListLocked(subscriptionID)
}

// visibleNodeCount is how many nodes would still be usable if these were hidden.
func (a *App) visibleNodeCount(subscriptionID string, alsoHiding []string) int {
	hiding := make(map[string]struct{}, len(alsoHiding))
	for _, name := range alsoHiding {
		hiding[name] = struct{}{}
	}
	for _, name := range a.hiddenNodeNames(subscriptionID) {
		hiding[name] = struct{}{}
	}

	nodes := a.whiteVPNNodesSnapshot(subscriptionID)
	if len(nodes) == 0 {
		// Nothing is known about this subscription yet, so there is nothing to
		// protect and no reason to refuse.
		return 1
	}
	remaining := 0
	for _, node := range nodes {
		if _, gone := hiding[node.Name]; !gone {
			remaining++
		}
	}
	return remaining
}

// hiddenNodeNames is what the user has taken out of one subscription.
func (a *App) hiddenNodeNames(subscriptionID string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.state.HiddenNodes[subscriptionID]...)
}

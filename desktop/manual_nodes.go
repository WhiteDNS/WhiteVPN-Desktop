package main

// Editing and removing the configs a user added by hand.
//
// The Servers page could list manual configs, test them and connect through
// them, but not change or remove one — the only way to correct a typo in a
// config was to delete every manual config and import them all again.
//
// These go through their own entry points rather than exposing the profile CRUD
// directly, for three reasons the interface should not have to remember. A
// config that belongs to a subscription is not the user's to edit: it is a
// reading of what the provider is serving, it returns unchanged at the next
// refresh, and letting it through here would give someone a delete button that
// undoes itself. The cached node list has to be dropped, or the row survives its
// own deletion until the cache expires. And a config that is carrying traffic
// right now cannot simply vanish underneath the connection.

import (
	"fmt"
	"strings"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

// SaveManualNode stores an edited manual config and hands back the refreshed
// list, so the page that asked does not have to reload separately.
//
// An empty ID adds a config rather than changing one, which is what the same
// form does when it is opened on nothing.
func (a *App) SaveManualNode(profile model.V2RayProfile) (model.WhiteVPNNodeList, error) {
	profile.SubscriptionID = ""

	if id := strings.TrimSpace(profile.ID); id != "" {
		existing, ok := a.manualProfileByID(id)
		if !ok {
			return a.snapshotWhiteVPNNodes(model.ManualServerSourceID),
				fmt.Errorf("that config is no longer in the list")
		}
		if existing.SubscriptionID != "" {
			return a.snapshotWhiteVPNNodes(model.ManualServerSourceID),
				fmt.Errorf("configs that come from a subscription cannot be edited here")
		}
	}

	// Rejected before it is stored rather than after: a profile that cannot be
	// expressed as a share link is one the engine cannot be built from either,
	// and storing it would put a row on the page that fails at connect with no
	// clue as to why.
	normalized := profiles.NormalizeV2RayProfile(profile)
	if _, err := profiles.ExportV2RayProfile(normalized); err != nil {
		return a.snapshotWhiteVPNNodes(model.ManualServerSourceID),
			fmt.Errorf("that config is not complete: %w", err)
	}

	if _, err := a.SaveV2RayProfile(profile); err != nil {
		return a.snapshotWhiteVPNNodes(model.ManualServerSourceID), err
	}

	a.forgetWhiteVPNNodes(model.ManualServerSourceID)
	if a.connectedThroughManualConfigs() {
		// The running engine was built from the previous configuration and keeps
		// running on it. Saying so beats a page that shows the new details over a
		// connection using the old ones.
		a.appendRuntimeLog("a manual config changed; reconnect for it to take effect")
	}
	return a.ListSubscriptionNodes(model.ManualServerSourceID, true)
}

// DeleteManualNodes removes manual configs by the profile IDs their rows carry.
func (a *App) DeleteManualNodes(ids []string) (model.WhiteVPNNodeList, error) {
	wanted := make([]string, 0, len(ids))
	for _, id := range ids {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			wanted = append(wanted, trimmed)
		}
	}
	if len(wanted) == 0 {
		return a.snapshotWhiteVPNNodes(model.ManualServerSourceID), nil
	}

	for _, id := range wanted {
		profile, ok := a.manualProfileByID(id)
		if !ok {
			continue
		}
		if profile.SubscriptionID != "" {
			return a.snapshotWhiteVPNNodes(model.ManualServerSourceID),
				fmt.Errorf("configs that come from a subscription cannot be deleted here; remove the subscription instead")
		}
		if a.manualProfileIsCarryingTraffic(profile) {
			return a.snapshotWhiteVPNNodes(model.ManualServerSourceID),
				fmt.Errorf("%q is carrying traffic right now; disconnect before deleting it", profile.Name)
		}
	}

	if _, err := a.DeleteV2RayProfiles(wanted); err != nil {
		return a.snapshotWhiteVPNNodes(model.ManualServerSourceID), err
	}

	a.forgetWhiteVPNNodes(model.ManualServerSourceID)
	// A refresh rather than a snapshot: the list has to be rebuilt from what is
	// left, and deleting the last manual config legitimately empties it.
	list, err := a.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil && len(a.manualProfiles()) == 0 {
		return model.WhiteVPNNodeList{Nodes: []model.WhiteVPNNode{}}, nil
	}
	return list, err
}

// ManualNodeProfile is the stored config behind a row, for the edit form to open
// on. Nodes from the catalogue or a subscription have none, which is how the
// interface knows not to offer the form at all.
func (a *App) ManualNodeProfile(id string) (model.V2RayProfile, error) {
	profile, ok := a.manualProfileByID(strings.TrimSpace(id))
	if !ok {
		return model.V2RayProfile{}, fmt.Errorf("that config is no longer in the list")
	}
	if profile.SubscriptionID != "" {
		return model.V2RayProfile{}, fmt.Errorf("that config comes from a subscription and is not editable")
	}
	return profile, nil
}

func (a *App) manualProfileByID(id string) (model.V2RayProfile, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, profile := range a.state.V2RayProfiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return model.V2RayProfile{}, false
}

func (a *App) manualProfiles() []model.V2RayProfile {
	a.mu.Lock()
	defer a.mu.Unlock()
	manual := make([]model.V2RayProfile, 0, len(a.state.V2RayProfiles))
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == "" {
			manual = append(manual, profile)
		}
	}
	return manual
}

// connectedThroughManualConfigs reports whether the running connection was built
// from the manual list.
func (a *App) connectedThroughManualConfigs() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.Runtime.Status != model.RuntimeDisconnected &&
		a.state.SelectedSubscriptionID == model.ManualServerSourceID
}

// manualProfileIsCarryingTraffic reports whether this config is the one the live
// connection is using.
//
// The comparison is on the node name the runtime recorded, because that is what
// the engine selects by — the profile's own ID never reaches the engine.
func (a *App) manualProfileIsCarryingTraffic(profile model.V2RayProfile) bool {
	if !a.connectedThroughManualConfigs() {
		return false
	}
	link, err := profiles.ExportV2RayProfile(profiles.NormalizeV2RayProfile(profile))
	if err != nil {
		return false
	}

	a.mu.Lock()
	running := strings.TrimSpace(a.state.Runtime.NodeName)
	a.mu.Unlock()
	if running == "" {
		return false
	}

	for _, node := range a.whiteVPNNodesSnapshot(model.ManualServerSourceID) {
		if node.Link == link {
			return node.Name == running
		}
	}
	return false
}

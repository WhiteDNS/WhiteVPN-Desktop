package main

import (
	"fmt"
	"strings"

	"whitevpn-desktop/internal/model"
)

// Full connection data crosses the Wails boundary only for explicit editing.
func (a *App) GetV2RaySubscriptionForEdit(id string) (model.V2RaySubscription, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id = strings.TrimSpace(id)
	if model.IsBuiltInSubscription(id) {
		return model.V2RaySubscription{}, fmt.Errorf("built-in subscription is not editable")
	}
	sub, ok := findV2RaySubscription(a.state, id)
	if !ok {
		return model.V2RaySubscription{}, fmt.Errorf("subscription not found")
	}
	sub.PublicOnly = false
	return sub, nil
}

func (a *App) GetWhiteVPNSettingsForEdit() model.WhiteVPNSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	settings := settingsForThisMachine(model.NormalizeWhiteVPNSettings(model.CloneWhiteVPNSettings(a.state.WhiteVPN)))
	settings.PublicOnly = false
	return settings
}

func (a *App) GetConnectionProfileForEdit(id string) (model.ConnectionProfile, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.state.ConnectionProfiles {
		if p.ID == strings.TrimSpace(id) {
			p.PublicOnly = false
			return p, nil
		}
	}
	return model.ConnectionProfile{}, fmt.Errorf("connection profile not found")
}

func (a *App) GetSettingsProfileForEdit(id string) (model.SettingsProfile, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.state.SettingsProfiles {
		if p.ID == strings.TrimSpace(id) {
			p.PublicOnly = false
			return p, nil
		}
	}
	return model.SettingsProfile{}, fmt.Errorf("settings profile not found")
}

type NodeShare struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

// Export only explicitly named nodes from the already loaded source. No fetch
// or alternate source is selected by a request to copy/share a node.
func (a *App) ExportNodeLinks(subscriptionID string, names []string) ([]NodeShare, error) {
	if len(names) == 0 || len(names) > 10000 {
		return nil, fmt.Errorf("select nodes to export")
	}
	byName := make(map[string]model.WhiteVPNNode)
	for _, node := range a.whiteVPNNodesSnapshot(strings.TrimSpace(subscriptionID)) {
		byName[node.Name] = node
	}
	result := make([]NodeShare, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		node, found := byName[name]
		if !found {
			return nil, fmt.Errorf("selected node is no longer loaded; refresh the list")
		}
		if node.Link != "" && !node.CredentialRequired {
			result = append(result, NodeShare{Name: name, Link: node.Link})
		}
	}
	return result, nil
}

func (a *App) sourceCredentialError(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, sub := range a.state.V2RaySubscriptions {
		if (sub.ID == id || model.IsEverySubscription(id)) && sub.CredentialRequired {
			return model.ErrCredentialsRequired
		}
	}
	if id == model.ManualServerSourceID || model.IsEverySubscription(id) {
		for _, p := range a.state.V2RayProfiles {
			if p.SubscriptionID == "" && p.CredentialRequired {
				return model.ErrCredentialsRequired
			}
		}
	}
	return nil
}

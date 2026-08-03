package profiles

import (
	"encoding/json"
	"os"

	"whitevpn-desktop/internal/model"
)

// LegacyImport is what a WhiteDNS Desktop install has that is worth carrying
// over. Counts are reported separately so the UI can describe the offer without
// the caller having to walk the profiles itself.
type LegacyImport struct {
	Available     bool   `json:"available"`
	Profiles      int    `json:"profiles"`
	Subscriptions int    `json:"subscriptions"`
	FrontingIPs   int    `json:"frontingIps"`
	SourcePath    string `json:"sourcePath"`

	profiles      []model.V2RayProfile
	subscriptions []model.V2RaySubscription
	settings      []model.V2RaySettingsProfile
	frontingIPs   []string
}

// ReadLegacyImport parses a WhiteDNS Desktop state file. It only ever reads:
// the other app's directory is never created, written to or modified, and every
// failure — missing file, unreadable, malformed — is reported as "nothing to
// import" rather than an error, because not having WhiteDNS Desktop installed
// is the normal case.
func ReadLegacyImport(path string) LegacyImport {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LegacyImport{}
	}

	var state model.AppState
	if err := json.Unmarshal(raw, &state); err != nil {
		return LegacyImport{}
	}

	out := LegacyImport{
		SourcePath:    path,
		profiles:      normalizeV2RayProfiles(state.V2RayProfiles),
		subscriptions: normalizeV2RaySubscriptions(state.V2RaySubscriptions),
		settings:      normalizeV2RaySettingsProfiles(state.V2RaySettingsProfiles),
	}
	for _, ip := range state.WhiteDNSVPNFrontingIPs {
		if ip != "" {
			out.frontingIPs = append(out.frontingIPs, ip)
		}
	}

	out.Profiles = len(out.profiles)
	out.Subscriptions = len(out.subscriptions)
	out.FrontingIPs = len(out.frontingIPs)
	out.Available = out.Profiles > 0 || out.Subscriptions > 0 || out.FrontingIPs > 0
	return out
}

// Apply copies the imported profiles onto a state. Anything already present
// wins, so importing can only ever add.
func (l LegacyImport) Apply(state model.AppState) model.AppState {
	if !l.Available {
		return state
	}

	existing := make(map[string]struct{}, len(state.V2RayProfiles))
	for _, profile := range state.V2RayProfiles {
		existing[profile.ID] = struct{}{}
	}
	for _, profile := range l.profiles {
		if _, seen := existing[profile.ID]; seen {
			continue
		}
		existing[profile.ID] = struct{}{}
		state.V2RayProfiles = append(state.V2RayProfiles, profile)
	}

	existingSubs := make(map[string]struct{}, len(state.V2RaySubscriptions))
	for _, subscription := range state.V2RaySubscriptions {
		existingSubs[subscription.ID] = struct{}{}
	}
	for _, subscription := range l.subscriptions {
		if _, seen := existingSubs[subscription.ID]; seen {
			continue
		}
		existingSubs[subscription.ID] = struct{}{}
		state.V2RaySubscriptions = append(state.V2RaySubscriptions, subscription)
	}

	existingSettings := make(map[string]struct{}, len(state.V2RaySettingsProfiles))
	for _, settings := range state.V2RaySettingsProfiles {
		existingSettings[settings.ID] = struct{}{}
	}
	for _, settings := range l.settings {
		if _, seen := existingSettings[settings.ID]; seen {
			continue
		}
		existingSettings[settings.ID] = struct{}{}
		state.V2RaySettingsProfiles = append(state.V2RaySettingsProfiles, settings)
	}

	knownIPs := make(map[string]struct{}, len(state.WhiteDNSVPNFrontingIPs))
	for _, ip := range state.WhiteDNSVPNFrontingIPs {
		knownIPs[ip] = struct{}{}
	}
	for _, ip := range l.frontingIPs {
		if _, seen := knownIPs[ip]; seen {
			continue
		}
		knownIPs[ip] = struct{}{}
		state.WhiteDNSVPNFrontingIPs = append(state.WhiteDNSVPNFrontingIPs, ip)
	}

	return state
}

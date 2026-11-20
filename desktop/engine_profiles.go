package main

import (
	"path/filepath"
	"runtime"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/securestore"
)

// The versioned path is independent of legacy state.json, so an older desktop
// binary cannot overwrite the new engine catalog when saving its settings.
func (a *App) initEngineProfiles() {
	a.engineProfilesMu.Lock()
	defer a.engineProfilesMu.Unlock()
	protector, err := securestore.NewUserProtector("engine-profiles/v1")
	if err == nil {
		vault := securestore.New(filepath.Join(a.configDir, "state-v2", "engine-profiles.vault"), protector)
		a.engineProfiles, err = engineprofiles.Open(vault)
	}
	a.engineProfilesErr = err
}

func (a *App) engineProfileStore() (*engineprofiles.Store, error) {
	a.engineProfilesMu.Lock()
	defer a.engineProfilesMu.Unlock()
	if a.engineProfilesErr != nil {
		return nil, a.engineProfilesErr
	}
	if a.engineProfiles == nil {
		return nil, securestore.ErrUnavailable
	}
	return a.engineProfiles, nil
}

func (a *App) ListEngineProfiles() ([]engineprofiles.Summary, error) {
	a.engineDataMu.RLock()
	defer a.engineDataMu.RUnlock()
	s, err := a.engineProfileStore()
	if err != nil {
		return nil, err
	}
	return s.List(), nil
}

// This is the only profile API that returns the complete credential config.
// Call it only when opening the editor, not to populate lists or home state.
func (a *App) GetEngineProfileForEdit(id string) (engineprofiles.Profile, error) {
	a.engineDataMu.RLock()
	defer a.engineDataMu.RUnlock()
	s, err := a.engineProfileStore()
	if err != nil {
		return engineprofiles.Profile{}, err
	}
	return s.ForEdit(id)
}

// JSON input gives the backend ownership of strict size/field validation rather
// than allowing the binding decoder to silently discard unknown fields.
func (a *App) SaveEngineProfile(rawJSON string) (engineprofiles.Summary, error) {
	p, err := engineprofiles.Decode([]byte(rawJSON))
	if err != nil {
		return engineprofiles.Summary{}, err
	}
	// Release the data gate before invoking event hooks or Wails callbacks.
	summary, err := func() (engineprofiles.Summary, error) {
		a.engineDataMu.RLock()
		defer a.engineDataMu.RUnlock()
		s, err := a.engineProfileStore()
		if err != nil {
			return engineprofiles.Summary{}, err
		}
		return s.Save(p)
	}()
	if err == nil {
		a.emit("engine-profiles:changed", summary)
	}
	return summary, err
}

func (a *App) DeleteEngineProfile(id string, revision uint64) error {
	err := func() error {
		a.engineDataMu.RLock()
		defer a.engineDataMu.RUnlock()
		s, err := a.engineProfileStore()
		if err != nil {
			return err
		}
		return s.Delete(id, revision)
	}()
	if err == nil {
		a.emit("engine-profiles:changed", struct {
			ID string `json:"id"`
		}{ID: id})
	}
	return err
}

// Availability reports implemented runtime support, not merely editable kinds.
// Runtime backends are registered by subsequent integration steps.
func (a *App) GetEngineAvailability() []engineprofiles.Availability {
	_, storeErr := a.engineProfileStore()
	out := make([]engineprofiles.Availability, 0, 6)
	for _, kind := range engineprofiles.Kinds() {
		reason := "backend-not-installed"
		if runtime.GOOS != "windows" {
			reason = "platform-unsupported"
		} else if storeErr != nil {
			reason = "credential-vault-unavailable"
		}
		out = append(out, engineprofiles.Availability{Kind: kind, Reason: reason, Capabilities: engineprofiles.Policy(kind)})
	}
	return out
}

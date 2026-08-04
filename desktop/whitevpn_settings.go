package main

import (
	"fmt"

	"whitevpn-desktop/internal/model"
)

// GetWhiteVPNSettings returns the settings the phone app exposes.
func (a *App) GetWhiteVPNSettings() model.WhiteVPNSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return model.NormalizeWhiteVPNSettings(a.state.WhiteVPN)
}

// SaveWhiteVPNSettings stores them, repaired.
//
// Normalising on the way in rather than trusting the form means a value that
// arrives out of range - from an edited state file, or a control that let
// something through - is corrected once, here, instead of reaching the engine
// and failing there where the cause is much harder to see.
func (a *App) SaveWhiteVPNSettings(settings model.WhiteVPNSettings) (model.AppState, error) {
	normalized := model.NormalizeWhiteVPNSettings(settings)

	a.mu.Lock()
	a.state.WhiteVPN = normalized
	state, err := a.saveLocked()
	a.mu.Unlock()

	if err != nil {
		return state, fmt.Errorf("save settings: %w", err)
	}
	return state, nil
}

package main

import (
	"fmt"

	"whitevpn-desktop/internal/model"
)

// The first-run gate, as the phone has it.
//
// Acceptance is versioned rather than a boolean: when the policy changes, the
// version goes up and the gate returns, which is the only way an acceptance can
// mean anything about what was actually agreed to.

// GetPrivacyPolicyVersion is the version the app currently asks acceptance for.
// The interface compares it against what was accepted rather than holding its
// own copy of the number, so the two cannot drift apart.
func (a *App) GetPrivacyPolicyVersion() int {
	return model.CurrentPrivacyPolicyID
}

// AcceptPrivacyPolicy records that this version was accepted.
func (a *App) AcceptPrivacyPolicy() (model.AppState, error) {
	a.mu.Lock()
	a.state.WhiteVPN.AcceptedPrivacyPolicyVersion = model.CurrentPrivacyPolicyID
	state, err := a.saveLocked()
	a.mu.Unlock()

	if err != nil {
		return state, fmt.Errorf("record privacy policy acceptance: %w", err)
	}
	return state, nil
}

// privacyPolicyAccepted reports whether the current version has been accepted.
func privacyPolicyAccepted(state model.AppState) bool {
	return state.WhiteVPN.AcceptedPrivacyPolicyVersion >= model.CurrentPrivacyPolicyID
}

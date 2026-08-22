// Package capability answers, per platform, what ways of moving traffic this
// machine can offer — and why, because “unsupported”, “helper not installed”,
// “approval required” and “available” lead to different actions by whoever
// reads them.
//
// Every operating system supplies two functions: Tunnel and SystemProxy. The
// answers are structured (model.TunnelCapability, model.SystemProxyCapability)
// rather than a boolean, so a Settings page can say what would change the
// answer instead of silently hiding the control.
package capability

import "whitevpn-desktop/internal/model"

// TunnelSelectable reports whether the interface may offer tunnel mode here.
// It is the question the old boolean answered; the structured result above it
// is how the rest of the app explains itself now.
func TunnelSelectable() bool {
	capability := Tunnel()
	return capability.Status == model.CapabilityAvailable ||
		capability.Status == model.CapabilityExperimental
}

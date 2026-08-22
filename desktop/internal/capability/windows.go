//go:build windows

package capability

import "whitevpn-desktop/internal/model"

// Windows raises the core through ShellExecuteExW with the runas verb: the UAC
// prompt is the approval, and it is part of every tunnel start. That is the
// platform's own model and this app keeps it.
func Tunnel() model.TunnelCapability {
	return model.TunnelCapability{
		Status:           model.CapabilityAvailable,
		RequiresApproval: true,
	}
}

// One setting governs the machine, and WinINET is where it lives.
func SystemProxy() model.SystemProxyCapability {
	return model.SystemProxyCapability{
		Status:   model.CapabilityAvailable,
		Scope:    "machine",
		Backends: []string{"wininet"},
	}
}

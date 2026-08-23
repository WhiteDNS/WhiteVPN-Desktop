//go:build darwin

package capability

import (
	"errors"

	"whitevpn-desktop/internal/macossvc"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/sysproxy"
)

// Tunnel on macOS runs only once the launch daemon is registered and approved.
// Each registration state is its own answer, because each one leads somewhere
// different: to System Settings, to a restart after an upgrade, or nowhere —
// it just works.
func Tunnel() model.TunnelCapability {
	service := macossvc.Daemon()
	registration, err := service.Registration()
	if errors.Is(err, macossvc.ErrUnsupportedPlatform) {
		return model.TunnelCapability{
			Status: model.CapabilityUnsupported,
			Reason: "tunnel mode needs macOS 13 or newer for its privileged daemon. Proxy mode works.",
		}
	}
	if err != nil {
		return model.TunnelCapability{
			Status: model.CapabilityHelperMissing,
			Reason: "the privileged daemon could not be checked (" + err.Error() + ").",
		}
	}
	switch registration {
	case macossvc.StatusNotRegistered:
		return model.TunnelCapability{
			Status: model.CapabilityHelperMissing,
			Reason: "the privileged helper is not installed yet. Enable it in Settings to be asked for approval.",
		}
	case macossvc.StatusNotFound:
		return model.TunnelCapability{
			Status: model.CapabilityHelperMissing,
			Reason: "the approved helper no longer matches this app. Reinstall WhiteVPN, or re-enable the helper in Settings.",
		}
	case macossvc.StatusRequiresApproval:
		return model.TunnelCapability{
			Status:           model.CapabilityRequiresApproval,
			RequiresApproval: true,
			Reason:           "approve WhiteVPN's helper in System Settings > General > Login Items, then try again.",
		}
	case macossvc.StatusEnabled:
		reply, err := service.Request("status", 3000)
		if err != nil {
			return model.TunnelCapability{
				Status: model.CapabilityHelperMissing,
				Reason: "the approved helper did not answer (" + err.Error() + "). Approve or reinstall it in Settings.",
			}
		}
		parsed, err := macossvc.ParseReply(reply)
		if err != nil {
			return model.TunnelCapability{
				Status: model.CapabilityHelperMissing,
				Reason: "the approved helper answered unintelligibly (" + err.Error() + "). Restart WhiteVPN.",
			}
		}
		if parsed.Version != macossvc.ProtocolVersion {
			return model.TunnelCapability{
				Status: model.CapabilityHelperMissing,
				Reason: "an older WhiteVPN helper is still registered. Approve the new one in System Settings > General > Login Items.",
			}
		}
		return model.TunnelCapability{Status: model.CapabilityExperimental, Experimental: true}
	default:
		return model.TunnelCapability{
			Status: model.CapabilityHelperMissing,
			Reason: "the privileged helper is in an unknown state. Reinstall WhiteVPN.",
		}
	}
}

// SystemProxy follows every enabled network service, because macOS keeps one
// configuration per service rather than one per machine.
func SystemProxy() model.SystemProxyCapability {
	targets, err := sysproxy.SystemStore().Targets()
	if err != nil || len(targets) == 0 {
		reason := "no enabled network service was found to configure."
		if err != nil {
			reason = "this machine's network services could not be listed (" + err.Error() + ")."
		}
		return model.SystemProxyCapability{
			Status: model.CapabilityUnsupported,
			Scope:  "manual",
			Reason: reason,
		}
	}
	backends := make([]string, 0, len(targets))
	for _, t := range targets {
		backends = append(backends, t.ID)
	}
	return model.SystemProxyCapability{
		Status:   model.CapabilityAvailable,
		Scope:    "machine",
		Backends: backends,
	}
}

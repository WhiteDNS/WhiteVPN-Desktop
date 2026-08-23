//go:build !windows && !linux && !darwin

package capability

import "whitevpn-desktop/internal/model"

// The platforms left have neither an elevation path nor a desktop proxy
// preference to write. Both answers say so plainly.
func Tunnel() model.TunnelCapability {
	return model.TunnelCapability{
		Status: model.CapabilityUnsupported,
		Reason: "tunnel mode is implemented on Windows, macOS and Linux.",
	}
}

func SystemProxy() model.SystemProxyCapability {
	return model.SystemProxyCapability{
		Status: model.CapabilityUnsupported,
		Scope:  "manual",
		Reason: "system proxy configuration is implemented on Windows, macOS and Linux.",
	}
}

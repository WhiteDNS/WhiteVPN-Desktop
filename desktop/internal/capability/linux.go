//go:build linux

package capability

import (
	"os"

	"whitevpn-desktop/internal/helper"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/sysproxy"
)

// Tunnel on Linux is honest in both directions: a portable build that cannot
// install a root-owned helper says so instead of weakening the privilege
// boundary to make a checkbox appear, and a packaged build with the helper
// installed is offered only behind the experimental switch while the live
// matrix proves itself.
func Tunnel() model.TunnelCapability {
	if _, err := helper.Detect(); err != nil {
		reason := "tunnel mode needs the privileged helper that comes with a distribution package (.deb, .rpm or AUR). Portable builds are proxy-only."
		if os.Getenv("APPIMAGE") != "" {
			reason = "an AppImage cannot install the root-owned helper tunnel mode needs. Install WhiteVPN from a distribution package, or keep using proxy mode."
		}
		return model.TunnelCapability{
			Status: model.CapabilityHelperMissing,
			Reason: reason,
		}
	}
	if !helper.ExperimentalEnabled() {
		return model.TunnelCapability{
			Status: model.CapabilityHelperMissing,
			Reason: "the privileged helper is installed, but Linux tunnel mode is still experimental: start the app with WHITEVPN_EXPERIMENTAL_TUN=1 to enable it for this release.",
		}
	}
	return model.TunnelCapability{
		Status:           model.CapabilityExperimental,
		RequiresApproval: true,
		Experimental:     true,
	}
}

// SystemProxy follows desktop preferences — GNOME's and KDE's side by side.
// Where neither answers (a bare window manager), the truth is that nothing on
// the machine will change and programs must be pointed here by hand.
func SystemProxy() model.SystemProxyCapability {
	backends := sysproxy.BackendNames()
	if len(backends) == 0 {
		return model.SystemProxyCapability{
			Status: model.CapabilityUnsupported,
			Scope:  "manual",
			Reason: "no desktop proxy setting was found on this machine. Use proxy-only mode and point your applications at the local port yourself.",
		}
	}
	return model.SystemProxyCapability{
		Status:   model.CapabilityAvailable,
		Scope:    "desktop",
		Backends: backends,
	}
}

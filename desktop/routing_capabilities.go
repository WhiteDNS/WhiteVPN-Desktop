package main

import (
	"runtime"

	"whitevpn-desktop/internal/capability"
	"whitevpn-desktop/internal/model"
)

// Whether this machine can run tunnel mode at all.
//
// A tunnel means creating a virtual adapter and rewriting the routing table,
// which needs privileges the app does not have and must ask for. How it asks
// is the platform's own business — UAC on Windows, polkit through the helper
// on Linux, SMAppService approval on macOS — but whether to offer the choice
// at all is answered here, next to the reason for the answer.
func (a *App) TunnelSupported() bool {
	return tunnelSupported()
}

// TunnelSupported reports whether tunnel mode can run here.
//
// Named for the question rather than the operating system. The interface has no
// business knowing which platforms have an elevation path; it needs to know
// whether to offer the choice, and that answer belongs here.
//
// Kept as a compatibility wrapper over the structured capability result: the
// frontend moves to GetRoutingCapabilities when it wants reasons, not just
// answers.
func tunnelSupported() bool {
	return capability.TunnelSelectable()
}

// GetRoutingCapabilities reports both ways of moving traffic with actionable
// explanations: what can run here now, and what would change the answer where
// something cannot.
func (a *App) GetRoutingCapabilities() model.RoutingCapabilities {
	return model.RoutingCapabilities{
		Platform:    runtime.GOOS,
		Tunnel:      capability.Tunnel(),
		SystemProxy: capability.SystemProxy(),
	}
}

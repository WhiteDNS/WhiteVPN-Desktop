// Package sysproxy points the machine at a local proxy, and puts back what it
// found.
//
// Without it the app in proxy mode starts a proxy nobody is talking to: the
// engine listens on 127.0.0.1, reports itself healthy, and not one byte of the
// user's traffic goes near it. That is what "connected, but nothing works"
// looked like, and no amount of reading the port off the dashboard fixes it,
// because the port was never the problem.
//
// Every change is preceded by reading what was there, so what was there can be
// put back — including after a crash, which is why State is something the
// caller can write to disk.
package sysproxy

import "strings"

// State is the machine's proxy configuration: what it was before this app
// touched it, or what it should be set to.
type State struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Override string `json:"override"`

	// Flags is WinINET's own word for how the connection is configured, kept
	// verbatim so a restore puts back exactly that. It carries more than this
	// app sets — auto-detect (WPAD) and a configuration script live in the same
	// field — and a VPN that silently switches off a machine's proxy
	// auto-detection is a VPN that breaks a corporate network on disconnect.
	Flags uint32 `json:"flags,omitempty"`
}

// DefaultBypass keeps local traffic off the proxy. Sending 127.0.0.1 through a
// proxy that lives on 127.0.0.1 is a loop, and a machine that cannot reach its
// own services while the VPN is up is a machine whose user turns the VPN off.
const DefaultBypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// SameAs reports whether two states describe the same configuration.
//
// Flags is deliberately not compared: enabling the proxy adds bits to whatever
// was there, so the flags after a change are not the flags that were asked for,
// and the question this answers is whether the settings took — which Enabled,
// Server and Override say.
func (s State) SameAs(other State) bool {
	return s.Enabled == other.Enabled &&
		strings.EqualFold(s.Server, other.Server) &&
		strings.EqualFold(s.Override, other.Override)
}

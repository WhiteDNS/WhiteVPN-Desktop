//go:build !windows

package session

// The adapter cannot be inspected here yet, which is not the same as the adapter
// being broken.
//
// This used to return a plain error, and because connecting treats a failed
// verification as a failed connection, the tunnel could never be used on macOS
// or Linux at all — "not implemented" was being reported to users as "your
// tunnel does not work". Saying it is unverifiable lets the connection stand and
// leaves the caveat where someone can act on it.
func verifyTunnel(string, bool) error {
	return errTunnelUnverifiable
}

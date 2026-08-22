//go:build !windows && !linux

package engine

import "errors"

// Windows has its elevation prompt and Linux has its helper. macOS gets its
// own launch daemon; until that work lands this refuses plainly rather than
// pretending to have tried: a tunnel that silently is not one is worse than a
// clear no.
func startElevatedChild(string, string, string, string) (childProcess, error) {
	return nil, errors.New(
		"engine: a tunnel needs elevated rights, which are not wired up on this platform yet. " +
			"Turn the tunnel off and use the local proxy instead")
}

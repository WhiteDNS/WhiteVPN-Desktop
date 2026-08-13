//go:build !windows && !linux

package engine

import "errors"

// Windows has its elevation prompt and Linux has pkexec. macOS has neither
// implemented here, so this refuses plainly rather than pretending to have
// tried: a tunnel that silently is not one is worse than a clear no.
func startElevatedChild(string, string, string) (childProcess, error) {
	return nil, errors.New(
		"engine: a tunnel needs elevated rights, which are only wired up on Windows and Linux. " +
			"Turn the tunnel off and use the local proxy instead")
}

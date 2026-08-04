//go:build !windows

package engine

import "errors"

// Elevating for a tunnel is a Windows arrangement. On macOS and Linux the
// tunnel path is not supported yet at all, so this refuses plainly rather than
// pretending to have tried.
func startElevatedChild(string, string, string) (childProcess, error) {
	return nil, errors.New("engine: running the core elevated is only implemented on Windows")
}

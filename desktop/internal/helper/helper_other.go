//go:build !linux

package helper

import "errors"

// Detect has no meaning off Linux: only Linux installs a root-owned helper at
// a fixed path. Callers on other platforms take their own routes (Windows
// elevates the extracted core through UAC; macOS talks to its launch daemon).
func Detect() (*Install, error) {
	return nil, errors.New("helper: this platform has no installed privileged component")
}

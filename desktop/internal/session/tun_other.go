//go:build !windows

package session

import "fmt"

func verifyTunnel(device string, _ bool) error {
	return fmt.Errorf("adapter verification for %q is only implemented on Windows", device)
}

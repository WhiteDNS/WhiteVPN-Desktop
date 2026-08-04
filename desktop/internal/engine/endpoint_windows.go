package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// defaultPipeSecurity restricts the pipe to SYSTEM and the Administrators group.
// The core runs elevated so it can create the tunnel adapter, and the control
// channel to something that privileged should not be open to every process on
// the machine.
const defaultPipeSecurity = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

func generateEndpoint() (string, error) {
	// A random name per run, so a stale or squatted pipe from an earlier run
	// cannot be mistaken for this one's.
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(`\\.\pipe\WhiteVpnEngine.%s`, hex.EncodeToString(suffix[:])), nil
}

func listen(endpoint, securityDescriptor string) (net.Listener, error) {
	if securityDescriptor == "" {
		securityDescriptor = defaultPipeSecurity
	}
	return winio.ListenPipe(endpoint, &winio.PipeConfig{
		SecurityDescriptor: securityDescriptor,
		// Byte mode: the protocol frames itself, and message mode would impose a
		// second set of boundaries to keep in agreement with the first.
		MessageMode: false,
	})
}

// cleanupEndpoint is a no-op on Windows: a named pipe disappears with its
// listener rather than leaving anything on disk.
func cleanupEndpoint(string) {}

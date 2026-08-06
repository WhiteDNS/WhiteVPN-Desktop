package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

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
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, fmt.Errorf("read current Windows user for pipe ACL: %w", err)
		}
		securityDescriptor = pipeSecurityDescriptor(user.User.Sid.String())
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

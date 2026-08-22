//go:build !windows

package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// The core's non-Windows entry point treats a numeric argument as a TCP port on
// loopback and anything else as a unix socket path. A unix socket is used here:
// it can be given filesystem permissions, whereas a loopback port is reachable
// by every local process.

func generateEndpoint() (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return filepath.Join(runtimeDir(), fmt.Sprintf("whitevpn-engine-%s.sock", hex.EncodeToString(suffix[:]))), nil
}

// runtimeDir prefers the user's own runtime directory: it is what the
// privileged helper checks ownership of, and on a systemd system it is
// per-user and mounted noexec. Falling back to TempDir keeps development and
// unusual sessions working — including sessions where XDG_RUNTIME_DIR is set
// to something that is not a usable absolute path.
func runtimeDir() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); filepath.IsAbs(dir) {
		return dir
	}
	return os.TempDir()
}

func listen(endpoint, _ string) (net.Listener, error) {
	// A socket left behind by a previous run would make Listen fail with "address
	// already in use" even though nothing is serving it.
	_ = os.Remove(endpoint)
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, err
	}
	// Owner only. The socket carries control of a privileged process.
	if err := os.Chmod(endpoint, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func cleanupEndpoint(endpoint string) {
	_ = os.Remove(endpoint)
}

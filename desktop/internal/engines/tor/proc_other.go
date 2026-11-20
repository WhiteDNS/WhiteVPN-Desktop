//go:build !windows

package tor

import (
	"os/exec"
	"time"
)

// Nothing to hide: only Windows attaches a console window to a child process.
func configureCommand(*exec.Cmd) {}

func torPath(path string) string { return path }

// shortcut: outside Windows the transports are not tracked by PID; they rely on
// Tor terminating them and on TOR_PT_EXIT_ON_STDIN_CLOSE. Track them here when
// the macOS/Linux builds ship Tor.
type child struct{ pid int }

func childrenOf(int) []child { return nil }

func (child) gone(time.Duration) bool { return true }
func (child) kill()                   {}
func (child) release()                {}

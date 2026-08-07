//go:build !windows

package session

import "os/exec"

// Only Windows gives a console program a window to hide.
func hideConsoleWindow(_ *exec.Cmd) {}

//go:build !windows

package engine

import "os/exec"

// Nothing to hide: only Windows attaches a console window to a child process.
func configureCommand(*exec.Cmd) {}

//go:build !windows

package firewall

import "os/exec"

func hideConsoleWindow(_ *exec.Cmd) {}

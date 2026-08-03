//go:build !windows

package appdata

import "os/exec"

func hideConsoleWindow(_ *exec.Cmd) {}

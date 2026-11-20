//go:build !windows

package psiphon

import "os/exec"

func configureCommand(*exec.Cmd) {}

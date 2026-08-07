//go:build windows

package session

import (
	"os/exec"
	"syscall"
)

// createNoWindow stops a console program putting a window on screen.
//
// PowerShell is a console program, so starting one from a GUI app flashes a
// window over the interface. Reading the tunnel's routes is polled while the
// adapter comes up, so this was not one flash but a stutter of them across every
// connect in tunnel mode — reported by a user as, fairly, "very ugly".
//
// `internal/firewall` and `internal/appdata` each already had this file. This
// package ran a command without it.
const createNoWindow = 0x08000000

func hideConsoleWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}

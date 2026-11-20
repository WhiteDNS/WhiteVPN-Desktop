package psiphon

import (
	"os/exec"
	"syscall"
)

// The ConsoleClient is a console program; started from the GUI it would open
// a console window over the app.
func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

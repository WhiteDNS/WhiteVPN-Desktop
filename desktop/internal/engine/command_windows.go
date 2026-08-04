package engine

import (
	"os/exec"
	"syscall"
)

// createNoWindow keeps the core from opening a console.
//
// The engine is a console application, so Windows gives it a console window
// unless told otherwise, and starting it from a GUI app pops one up over the
// interface. The window is not diagnostic — its output is already captured
// through Stdout and Stderr and shown on the Logs page.
const createNoWindow = 0x08000000

func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}

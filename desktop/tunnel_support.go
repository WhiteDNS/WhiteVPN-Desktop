package main

// Whether this machine can run tunnel mode at all.
//
// A tunnel means creating a virtual adapter and rewriting the routing table,
// which needs privileges the app does not have and must ask for. Asking is the
// part that is platform-specific.
//
// Windows has ShellExecuteExW with the `runas` verb. Linux has pkexec, which
// puts the prompt in the desktop's own polkit agent and leaves the interface
// running as the user — engine.startElevatedChild has had that path since
// August, and this function was never updated to admit it, so the tunnel was
// built on Linux and then never offered to anyone.
//
// macOS still has neither, and the original reason stands there: a switch that
// can only fail is worse than one that is absent, because the missing one does
// not waste somebody's evening on an accurate sentence about an unimplemented
// function.
//
// That reasoning is also why Linux is a question rather than a constant. Where
// polkit is not installed, pkexec cannot raise the core and the switch would
// fail every time it was touched — so it is offered where it can work and
// withheld where it cannot, which on Linux is a property of the machine rather
// than of the operating system.

import (
	"os"
	"os/exec"
	"runtime"
)

// TunnelSupported reports whether tunnel mode can run here.
//
// Named for the question rather than the operating system. The interface has no
// business knowing which platforms have an elevation path; it needs to know
// whether to offer the choice, and that answer belongs here next to the reason
// for it.
func (a *App) TunnelSupported() bool {
	return tunnelSupported()
}

func tunnelSupported() bool {
	// Kept in one function rather than a build-tagged set of files, so that the
	// day macOS gains an elevation path this reads as a list with something
	// added to it rather than a file somebody has to find.
	switch runtime.GOOS {
	case "windows":
		return true
	case "linux":
		return linuxCanElevate()
	default:
		return false
	}
}

// linuxCanElevate reports whether the core can actually be raised on this
// machine.
//
// Root already needs nothing: elevate_linux.go starts the core directly rather
// than asking again, which is what a user running the app under sudo gets and
// what the integration test in internal/engine exercises.
//
// Otherwise it comes down to pkexec being installed. Checking for the binary is
// not proof that the polkit policy will authorise the call — a machine can have
// pkexec and still decline — but declining is an answer a user can act on,
// where a missing pkexec is a switch that cannot work at all.
func linuxCanElevate() bool {
	if os.Geteuid() == 0 {
		return true
	}
	_, err := exec.LookPath("pkexec")
	return err == nil
}

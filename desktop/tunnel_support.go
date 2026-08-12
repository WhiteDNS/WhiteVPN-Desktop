package main

// Whether this machine can run tunnel mode at all.
//
// A tunnel means creating a virtual adapter and rewriting the routing table,
// which needs privileges the app does not have and must ask for. Asking is the
// part that is platform-specific: Windows has ShellExecuteExW with the `runas`
// verb, and engine.startElevatedChild is implemented there and nowhere else.
// On Linux and macOS it returns
//
//	engine: running the core elevated is only implemented on Windows
//
// which is where a Linux user landed after turning the switch on: an accurate
// sentence about an unimplemented function, offered as though their connection
// had failed.
//
// The rest of the tunnel is not the problem. The unix socket the elevated core
// would connect back on is already built, permissioned and cleaned up on every
// platform; what is missing is only the launcher that raises the core. Until
// that exists the control should not be offered, because a switch that can only
// fail is worse than one that is absent — the missing one does not waste
// somebody's evening.

import "runtime"

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
	// Kept as one expression rather than a build-tagged pair of files, so that
	// the day macOS or Linux gains an elevation path this reads as a list with
	// something added to it rather than a file somebody has to find.
	return runtime.GOOS == "windows"
}

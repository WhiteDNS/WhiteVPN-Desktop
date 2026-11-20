//go:build !windows

package psiphon

import "os/exec"

func configureCommand(*exec.Cmd) {}

// shortcut: no job object outside Windows, so a crashed app can leave the
// worker running; upgrade when the engines ship for macOS/Linux.
func bindToApp(int) error { return nil }

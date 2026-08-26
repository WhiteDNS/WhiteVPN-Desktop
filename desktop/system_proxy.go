package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"whitevpn-desktop/internal/sysproxy"
)

// The machine-facing calls, as variables so the paths that go wrong can be
// tested. Restoring badly is the failure that matters here, and reproducing it
// against the real ones would mean a test that reconfigures the developer's own
// network.
var (
	systemProxyCurrent = sysproxy.Current
	systemProxyApply   = sysproxy.Apply
	systemProxyVerify  = sysproxy.Verify
)

// The machine's proxy settings, as they were before this app changed them.
//
// On disk, because a crash is exactly when they matter: the process that would
// have put them back is gone, and the user is left with a browser pointed at a
// port nothing is listening on. The file is written before the change and
// removed after the change is undone, so its presence at startup means the last
// run did not finish.
const systemProxyBackupName = "system-proxy.json"

func (a *App) systemProxyBackupPath() string {
	return filepath.Join(a.configDir, systemProxyBackupName)
}

// captureSystemProxy points the machine at the local proxy and remembers what
// it replaced.
//
// Only in proxy mode: with the tunnel up the routing is the tunnel's job, and
// setting a proxy as well would send some applications through it twice.
func (a *App) captureSystemProxy(port int) error {
	if port <= 0 {
		return fmt.Errorf("system proxy: invalid local proxy port %d", port)
	}
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	next, err := sysproxy.Pointing(endpoint)
	if err != nil {
		return err
	}

	// A backup already on disk is the last run's, and it is left alone.
	//
	// Its presence means the machine was never given back: a restore that
	// failed, a dismissed administrator prompt, a process that died. What the
	// machine holds now is this app's own proxy, so reading it and filing it as
	// "what was there before" would overwrite the only record of the user's real
	// settings with a local port. Every restore after that would put the machine
	// back to 127.0.0.1, delete the record, and report success — which is how a
	// disconnect came to leave macOS pointed at a proxy nothing was listening on.
	previous, held := a.readSystemProxyBackup()
	if !held {
		// The record of what was there goes down before anything is changed. A
		// failure after this point leaves a machine that can be put back; a
		// failure before it changes nothing.
		previous, err = systemProxyCurrent()
		if err != nil {
			return err
		}
		if err := a.writeSystemProxyBackup(previous); err != nil {
			return fmt.Errorf("could not record the current settings first: %w", err)
		}
	}
	if err := systemProxyApply(next); err != nil {
		return err
	}
	// Read back rather than assume. Another program can be writing the same
	// key, and a badge claiming the machine uses this proxy when it does not is
	// worse than no badge.
	if err := systemProxyVerify(next); err != nil {
		return err
	}

	a.mu.Lock()
	a.state.Runtime.SystemProxy = true
	a.state.Runtime.SystemProxyStranded = false
	a.mu.Unlock()
	a.appendRuntimeLog(fmt.Sprintf(
		"system proxy set to %s, replacing %q (enabled=%t)", endpoint, previous.Server, previous.Enabled))
	return nil
}

// restoreSystemProxy puts back whatever was there before, and is safe to call
// when nothing was changed.
func (a *App) restoreSystemProxy() {
	previous, ok := a.readSystemProxyBackup()
	if !ok {
		return
	}
	// If the machine already holds what the backup asks for, there is nothing to
	// put back and nothing to ask permission for.
	//
	// This is the ordinary case at startup after a restore that reported failure
	// but had in fact worked, and on macOS it is the difference between that
	// costing nothing and costing an administrator prompt at every launch,
	// forever, for a machine that was never wrong. It also means a user who fixed
	// their settings by hand is not asked to approve undoing it.
	if current, err := systemProxyCurrent(); err == nil && current.Satisfies(previous) {
		_ = os.Remove(a.systemProxyBackupPath())
		a.mu.Lock()
		a.state.Runtime.SystemProxy = false
		a.state.Runtime.SystemProxyStranded = false
		a.mu.Unlock()
		return
	}
	if err := systemProxyApply(previous); err != nil {
		// The backup stays: a restore that failed is one that still has to
		// happen, and the next start will try again.
		a.strandedSystemProxy(fmt.Sprintf("could not restore the system proxy: %v", err))
		return
	}
	// Read back, the same way capturing does, and for a sharper reason. On macOS
	// this runs through an administrator prompt: osascript reports whether it
	// managed to ask, not whether the answer changed anything, so a dismissed
	// prompt can return an error the caller never sees as one. Deleting the
	// backup on an unverified restore is what turns a recoverable state into a
	// permanent one.
	if err := systemProxyVerify(previous); err != nil {
		a.strandedSystemProxy(fmt.Sprintf("the system proxy did not go back: %v", err))
		return
	}
	_ = os.Remove(a.systemProxyBackupPath())
	a.mu.Lock()
	a.state.Runtime.SystemProxy = false
	a.state.Runtime.SystemProxyStranded = false
	a.mu.Unlock()
	a.appendRuntimeLog("system proxy restored")
}

// strandedSystemProxy records that the machine is still pointed at a proxy this
// app is no longer running.
//
// The engine really has stopped, so the connection is disconnected and says so.
// What has not happened is the machine being given back, and those are different
// facts: reporting only the first leaves somebody with no working network and
// nothing on screen that explains it. The backup is deliberately left where it
// is — startup tries again, and until it succeeds this is the only record of
// what the settings were.
func (a *App) strandedSystemProxy(reason string) {
	a.appendRuntimeLog(reason)
	a.mu.Lock()
	a.state.Runtime.SystemProxy = true
	a.state.Runtime.SystemProxyStranded = true
	a.mu.Unlock()
	a.appendRuntimeLog(
		"this machine is still pointed at a proxy that has stopped — reconnect, or restart the app to try again")
	a.emit("runtime:notice",
		"Disconnected, but this desktop's proxy settings could not be put back. Its network will not work until they are. Reconnect, or restart the app to try again.")
}

func (a *App) writeSystemProxyBackup(state sysproxy.State) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(a.systemProxyBackupPath(), encoded, 0o600)
}

func (a *App) readSystemProxyBackup() (sysproxy.State, bool) {
	raw, err := os.ReadFile(a.systemProxyBackupPath())
	if err != nil {
		return sysproxy.State{}, false
	}
	var state sysproxy.State
	if err := json.Unmarshal(raw, &state); err != nil {
		// Unreadable is worse than absent: it would keep the app trying to
		// restore something it cannot read, every start, forever.
		_ = os.Remove(a.systemProxyBackupPath())
		return sysproxy.State{}, false
	}
	return state, true
}

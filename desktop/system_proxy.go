package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"whitevpn-desktop/internal/sysproxy"
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
func (a *App) captureSystemProxy(port int) {
	if port <= 0 {
		return
	}
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	next, err := sysproxy.Pointing(endpoint)
	if err != nil {
		a.reportSystemProxyFailure(endpoint, err)
		return
	}
	previous, err := sysproxy.Current()
	if err != nil {
		a.reportSystemProxyFailure(endpoint, err)
		return
	}

	// The record of what was there goes down before anything is changed. A
	// failure after this point leaves a machine that can be put back; a failure
	// before it changes nothing.
	if err := a.writeSystemProxyBackup(previous); err != nil {
		a.reportSystemProxyFailure(endpoint, fmt.Errorf("could not record the current settings first: %w", err))
		return
	}
	if err := sysproxy.Apply(next); err != nil {
		a.reportSystemProxyFailure(endpoint, err)
		return
	}
	// Read back rather than assume. Another program can be writing the same
	// key, and a badge claiming the machine uses this proxy when it does not is
	// worse than no badge.
	if err := sysproxy.Verify(next); err != nil {
		a.reportSystemProxyFailure(endpoint, err)
		return
	}

	a.mu.Lock()
	a.state.Runtime.SystemProxy = true
	a.mu.Unlock()
	a.appendRuntimeLog(fmt.Sprintf(
		"system proxy set to %s, replacing %q (enabled=%t)", endpoint, previous.Server, previous.Enabled))
}

// reportSystemProxyFailure says so in both places a user might look. The
// connection itself is fine — the proxy is up and anything pointed at it by
// hand works — but silence here is the failure that looks like the VPN doing
// nothing at all.
func (a *App) reportSystemProxyFailure(endpoint string, err error) {
	a.appendRuntimeLog(fmt.Sprintf("could not point the system at %s: %v", endpoint, err))
	a.emit("runtime:error", fmt.Sprintf(
		"Connected, but Windows was not pointed at %s: %v. Set your browser's proxy to that address by hand, or use TUN mode.", endpoint, err))
}

// restoreSystemProxy puts back whatever was there before, and is safe to call
// when nothing was changed.
func (a *App) restoreSystemProxy() {
	previous, ok := a.readSystemProxyBackup()
	if !ok {
		return
	}
	if err := sysproxy.Apply(previous); err != nil {
		// The backup stays: a restore that failed is one that still has to
		// happen, and the next start will try again.
		a.appendRuntimeLog(fmt.Sprintf("could not restore the system proxy: %v", err))
		return
	}
	_ = os.Remove(a.systemProxyBackupPath())
	a.mu.Lock()
	a.state.Runtime.SystemProxy = false
	a.mu.Unlock()
	a.appendRuntimeLog("system proxy restored")
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

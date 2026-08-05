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
	previous, err := sysproxy.Set(endpoint)
	if err != nil {
		// Not fatal to the connection: the proxy is up and anything pointed at
		// it by hand still works. But the user has to be told, because
		// otherwise this is the failure that looks like the VPN doing nothing.
		a.appendRuntimeLog(fmt.Sprintf("could not point the system at %s: %v", endpoint, err))
		a.emit("runtime:error", fmt.Sprintf("Connected, but the system proxy could not be set: %v", err))
		return
	}
	if err := a.writeSystemProxyBackup(previous); err != nil {
		a.appendRuntimeLog(fmt.Sprintf("could not record the previous system proxy: %v", err))
	}
	a.mu.Lock()
	a.state.Runtime.SystemProxy = true
	a.mu.Unlock()
	a.appendRuntimeLog(fmt.Sprintf("system proxy set to %s", endpoint))
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

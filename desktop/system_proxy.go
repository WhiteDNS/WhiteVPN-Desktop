package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"whitevpn-desktop/internal/sysproxy"
)

// The machine's proxy settings, as they were before this app changed them.
//
// On disk, because a crash is exactly when they matter: the process that would
// have put them back is gone, and the user is left with a browser pointed at a
// port nothing is listening on. The file is written before the first change and
// rewritten after every single one, so whatever it says at startup is exactly
// what still needs putting back — no more and no less. Its presence at startup
// means the last run did not finish.
//
// The format is a sysproxy.Snapshot: one captured state per target (Windows'
// WinINET, Linux's GNOME/KDE backends, macOS's network services), plus the list
// of targets actually changed. The first format stored a single state for the
// whole machine; readers of that shape migrate it in place.
const systemProxyBackupName = "system-proxy.json"

func (a *App) systemProxyBackupPath() string {
	return filepath.Join(a.configDir, systemProxyBackupName)
}

// systemProxyStore reaches this platform's proxy settings. It is a variable so
// tests can stand in for the operating system this machine does not have.
var (
	systemProxyStore   = sysproxy.SystemStore
	systemProxyTargets = func() ([]sysproxy.Target, error) { return sysproxy.SystemStore().Targets() }
)

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

	store := systemProxyStore()
	snap, err := sysproxy.Capture(store)
	if err != nil {
		return err
	}
	snap.Platform = runtime.GOOS

	// The record of what was there goes down before anything is changed, and is
	// rewritten after each individual change so it stays true mid-transaction. A
	// failure after this point leaves a machine that can be put back; a failure
	// before it changes nothing.
	if err := a.writeSystemProxyBackup(snap); err != nil {
		return fmt.Errorf("could not record the current settings first: %w", err)
	}

	changed, err := sysproxy.Commit(store, snap, next, func(changed []string) {
		snap.Changed = changed
		if writeErr := a.writeSystemProxyBackup(snap); writeErr != nil {
			a.appendRuntimeLog(fmt.Sprintf("could not keep the proxy backup current: %v", writeErr))
		}
	})
	if err != nil {
		var te *sysproxy.TransactionError
		if errors.As(err, &te) && len(te.Unrolled) > 0 {
			// The file stays: those targets are still pointing here, and the
			// snapshot is the only record of where they should go back to.
			a.appendRuntimeLog(fmt.Sprintf(
				"the proxy change was rolled back except on %s; it will be retried at startup",
				strings.Join(te.Unrolled, ", ")))
			return err
		}
		_ = os.Remove(a.systemProxyBackupPath())
		return err
	}

	a.mu.Lock()
	a.state.Runtime.SystemProxy = true
	a.mu.Unlock()
	a.appendRuntimeLog(fmt.Sprintf(
		"system proxy set to %s on %s, replacing %s",
		endpoint, describeTargets(changed), describeCaptured(snap)))
	return nil
}

// restoreSystemProxy puts back whatever was there before, and is safe to call
// when nothing was changed — or when a previous run died before finishing,
// which is the case it exists for.
func (a *App) restoreSystemProxy() {
	snap, ok := a.readSystemProxyBackup()
	if !ok {
		return
	}
	store := systemProxyStore()

	err := sysproxy.Restore(store, snap, func(remaining []string) {
		snap.Changed = remaining
		if len(remaining) == 0 {
			return
		}
		if writeErr := a.writeSystemProxyBackup(snap); writeErr != nil {
			a.appendRuntimeLog(fmt.Sprintf("could not keep the proxy backup current: %v", writeErr))
		}
	})
	if err != nil {
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

func (a *App) writeSystemProxyBackup(snapshot sysproxy.Snapshot) error {
	snapshot.Version = sysproxy.SnapshotVersion
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return os.WriteFile(a.systemProxyBackupPath(), encoded, 0o600)
}

// readSystemProxyBackup returns the recorded snapshot, migrating the first
// format if it finds it.
//
// The first format held a single State for the whole machine, written by an app
// that applied it everywhere. It migrates by assigning that state to every
// target present today — precisely what the old restore did, minus the pretence
// that the machine had only one setting.
func (a *App) readSystemProxyBackup() (sysproxy.Snapshot, bool) {
	raw, err := os.ReadFile(a.systemProxyBackupPath())
	if err != nil {
		return sysproxy.Snapshot{}, false
	}

	var snapshot sysproxy.Snapshot
	if json.Unmarshal(raw, &snapshot) == nil &&
		snapshot.Version == sysproxy.SnapshotVersion &&
		len(snapshot.Targets) > 0 {
		return snapshot, true
	}

	var legacy sysproxy.State
	if err := json.Unmarshal(raw, &legacy); err != nil {
		// Unreadable is worse than absent: it would keep the app trying to
		// restore something it cannot read, every start, forever.
		_ = os.Remove(a.systemProxyBackupPath())
		return sysproxy.Snapshot{}, false
	}
	migrated, err := migrateLegacySnapshot(legacy)
	if err != nil {
		a.appendRuntimeLog(fmt.Sprintf(
			"discarding the old proxy backup: what it replaced can no longer be listed (%v)", err))
		_ = os.Remove(a.systemProxyBackupPath())
		return sysproxy.Snapshot{}, false
	}
	// Write the migration through so the next start reads it natively. Failure
	// here is not fatal: this copy works for now.
	_ = a.writeSystemProxyBackup(migrated)
	return migrated, true
}

func migrateLegacySnapshot(legacy sysproxy.State) (sysproxy.Snapshot, error) {
	targets, err := systemProxyTargets()
	if err != nil {
		return sysproxy.Snapshot{}, err
	}
	snapshot := sysproxy.Snapshot{
		Version:  sysproxy.SnapshotVersion,
		Platform: runtime.GOOS,
		Targets:  make(map[string]sysproxy.State, len(targets)),
	}
	for _, t := range targets {
		snapshot.Targets[t.ID] = legacy
		snapshot.Changed = append(snapshot.Changed, t.ID)
	}
	sort.Strings(snapshot.Changed)
	return snapshot, nil
}

func describeTargets(ids []string) string {
	if len(ids) == 0 {
		return "no settings it found"
	}
	return strings.Join(ids, ", ")
}

func describeCaptured(snap sysproxy.Snapshot) string {
	parts := make([]string, 0, len(snap.Targets))
	for _, id := range snap.Changed {
		state := snap.Targets[id]
		if state.Enabled {
			parts = append(parts, fmt.Sprintf("%s=%q", id, state.Server))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=off", id))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

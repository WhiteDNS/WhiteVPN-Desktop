package main

// Putting the app back to how it was on the day it was installed.
//
// This exists because nobody could get back there. A bug that only shows on a
// first launch — the catalogue missing from the subscriptions list, which is
// exactly what prompted this — is invisible to everyone who has used the app
// once, and that included every one of us. It took a user on a clean macOS
// install to find it, and confirming it on Windows meant writing a test rather
// than looking, because there was no way to make a Windows install fresh again
// short of deleting a folder by hand.
//
// A tool that can only be checked on hardware nobody has spare is a tool whose
// first-run experience never gets checked.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

// ResetAppData deletes everything this app has stored and returns the state a
// fresh install starts with.
//
// Everything means everything: settings, subscriptions, saved configs, the
// unpacked engine, the engine's working directories, validator results. What it
// does not touch is anything outside the app's own directory — the machine's
// proxy settings are put back by disconnecting, which is required before this
// can run at all.
func (a *App) ResetAppData() (model.AppState, error) {
	// Refused while anything is running, and not only for tidiness. The engine
	// is executing from the directory this is about to delete, its tunnel
	// adapter is up, and the machine's proxy settings are pointed at a port it
	// is listening on — with the record of what they were before sitting in the
	// same directory. Deleting that record while it is still needed would strand
	// the user's proxy settings with nothing left that knows how to put them
	// back.
	a.mu.Lock()
	status := a.state.Runtime.Status
	a.mu.Unlock()
	if status != model.RuntimeDisconnected && status != model.RuntimeFailed {
		return a.GetAppState(), fmt.Errorf("disconnect before resetting: the engine is running from the files this would delete")
	}
	if a.mihomo.current() != nil {
		return a.GetAppState(), fmt.Errorf("disconnect before resetting: a connection is still open")
	}

	if strings.TrimSpace(a.configDir) == "" {
		return a.GetAppState(), fmt.Errorf("this app does not know where its data lives, so it will not delete anything")
	}
	// The directory's own name is checked before anything is removed. This
	// deletes recursively, and a configDir that had somehow become "" or a
	// user's home would take the lot with it.
	if filepath.Base(filepath.Clean(a.configDir)) != appDataDirName {
		return a.GetAppState(), fmt.Errorf("refusing to delete %q: that is not this app's data directory", a.configDir)
	}

	if err := removeConfigDirContents(a.configDir); err != nil {
		return a.GetAppState(), fmt.Errorf("could not remove the stored data: %w", err)
	}

	// In memory as well as on disk. Leaving the old state loaded would have the
	// interface showing subscriptions and settings that no longer exist, and the
	// next save would write them all back.
	a.mu.Lock()
	a.state = model.DefaultAppState()
	a.ensureWhiteDNSVPNSubscriptionLocked()
	// A reset is a fresh install, and a fresh install offers the legacy import
	// again — but only if there is still something there to import.
	a.legacyImport = profiles.ReadLegacyImport(legacyWhiteDNSStatePath())
	next, err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		return a.GetAppState(), fmt.Errorf("the data was removed but the new state could not be written: %w", err)
	}

	a.forgetAllCachedNodes()
	a.clearProxyCountryCache()

	a.appendRuntimeLog("app data reset; everything is back to a fresh install")
	a.emit("runtime:state", a.currentRuntime())
	return next, nil
}

// removeConfigDirContents empties the directory without removing it.
//
// The directory itself stays because the app is running out of it and something
// may already hold a handle on it; recreating it under a running process is
// asking for trouble on Windows in particular.
func removeConfigDirContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var failed []string
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			// Kept going rather than stopping at the first: a file still held
			// open should not leave the rest of the reset half done, and naming
			// all of them at once beats one round trip per file.
			failed = append(failed, entry.Name())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("these could not be removed: %s", strings.Join(failed, ", "))
	}
	return nil
}

// ResetWhiteVPNSettings puts the settings back to a fresh install's and leaves
// everything else where it is.
//
// Separate from ResetAppData, which deletes everything and refuses to run while
// anything is connected. That is the right tool for "put this machine back to
// the day it was installed" and the wrong one for every ordinary case: somebody
// who has narrowed the connection down to one node, turned on a fronting IP and
// changed the DNS mode while chasing a problem wants those undone, and does not
// want to lose the subscriptions they pasted in, the delays they spent ten
// minutes measuring, or the connection they are reading the instructions over.
//
// So this touches settings and only settings. Subscriptions, imported and manual
// configs, hidden nodes, measured delays and validator results are all left
// alone, and a running connection keeps running: nothing here reaches the engine
// or the session. Settings that only apply at connect — the listening port, the
// tunnel — go back to their defaults and take effect the next time, which is the
// same thing changing them by hand does.
func (a *App) ResetWhiteVPNSettings() (model.AppState, error) {
	defaults := model.DefaultWhiteVPNSettings()

	a.mu.Lock()
	// Consent is a record of something the user did, not a preference they
	// configured. Clearing it would not put them back to a fresh install, it
	// would claim they never agreed, and then ask them again — so it carries
	// over.
	defaults.AcceptedPrivacyPolicyVersion = a.state.WhiteVPN.AcceptedPrivacyPolicyVersion
	// Run through the same normalisation a hand-edited save gets, so a default
	// that this machine cannot honour — the tunnel, where there is no way to
	// raise one — is corrected here rather than at connect.
	a.state.WhiteVPN = settingsForThisMachine(model.NormalizeWhiteVPNSettings(defaults))
	a.state.Theme = model.DefaultAppState().Theme
	// Which subscription is selected is a setting, and the phone resets it the
	// same way. The subscriptions themselves stay; only the choice of which one
	// the VPN connects through goes back to the built-in catalogue.
	a.state.SelectedSubscriptionID = whiteDNSVPNSubscriptionID
	state, err := a.saveLocked()
	a.mu.Unlock()

	if err != nil {
		return state, fmt.Errorf("reset settings: %w", err)
	}
	a.appendRuntimeLog("settings reset to their defaults — subscriptions, saved configs and test results were kept")
	// The tray reads the language and the status from the same state the page
	// does, so it is told rather than left to notice.
	a.notifyTray()
	a.emit("state:changed", state)
	return state, nil
}

package main

import (
	"errors"
	"os"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/sysproxy"
)

// The backup exists so that a crash is survivable: the machine's proxy has to
// go back to what it was, and the only record of what it was is this file.
func TestSystemProxyBackupSurvivesToBeRestored(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}

	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("a fresh directory holds no backup, so nothing should be restored")
	}

	want := sysproxy.State{Enabled: true, Server: "127.0.0.1:10808", Override: "<local>"}
	if err := app.writeSystemProxyBackup(want); err != nil {
		t.Fatal(err)
	}
	got, ok := app.readSystemProxyBackup()
	if !ok || !got.SameAs(want) {
		t.Fatalf("the backup did not survive: got %#v, want %#v", got, want)
	}
}

// A file that cannot be read is worse than none: kept, it would have the app
// trying to restore something it cannot understand on every start, forever.
func TestUnreadableSystemProxyBackupIsDiscarded(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	if err := os.WriteFile(app.systemProxyBackupPath(), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("expected an unreadable backup to be refused")
	}
	if _, err := os.Stat(app.systemProxyBackupPath()); !os.IsNotExist(err) {
		t.Fatal("expected an unreadable backup to be removed rather than retried forever")
	}
}

// Restoring when nothing was changed must be a no-op, because it runs on every
// stop — including the ones that follow a connection that never came up.
func TestRestoringWithNoBackupChangesNothing(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	app.state.Runtime.SystemProxy = true
	app.restoreSystemProxy()
	if !app.state.Runtime.SystemProxy {
		t.Fatal("with no backup there is nothing to restore, and nothing to report")
	}
}

// The failure this file exists for.
//
// A restore that did not happen leaves the machine pointed at this app and the
// backup on disk. Connecting again must not read that back and file it as "what
// was there before": the only record of the user's real settings would become a
// local port, and every restore after it would put the machine back to a proxy
// nothing is listening on and then delete the evidence.
func TestConnectingAgainDoesNotOverwriteAnUnusedBackup(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}

	original := sysproxy.State{Enabled: true, Server: "proxy.corp.example:8080", Override: "<local>"}
	if err := app.writeSystemProxyBackup(original); err != nil {
		t.Fatal(err)
	}

	// What the machine holds now is this app's own proxy, left behind by a
	// restore that failed.
	defer swapSystemProxyCalls(t,
		func() (sysproxy.State, error) {
			return sysproxy.State{Enabled: true, Server: "127.0.0.1:2080"}, nil
		},
		func(sysproxy.State) error { return nil },
		func(sysproxy.State) error { return nil },
	)()

	if err := app.captureSystemProxy(2080); err != nil {
		t.Fatal(err)
	}

	got, ok := app.readSystemProxyBackup()
	if !ok {
		t.Fatal("the backup was removed by a capture that should not have touched it")
	}
	if !got.SameAs(original) {
		t.Fatalf("the user's settings were overwritten with this app's own proxy: got %#v, want %#v", got, original)
	}
}

// A restore the machine refused is not a restore. The backup is what makes
// another attempt possible, so it stays, and the state says the machine is
// still pointed somewhere that has stopped answering.
func TestRefusedRestoreKeepsTheBackupAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		apply  func(sysproxy.State) error
		verify func(sysproxy.State) error
	}{
		{
			// macOS asks for an administrator password here. Dismissing it is
			// the ordinary way this fails.
			name:   "the machine refused the change",
			apply:  func(sysproxy.State) error { return errors.New("administrator approval failed") },
			verify: func(sysproxy.State) error { return nil },
		},
		{
			// osascript reports whether it managed to ask, not whether anything
			// changed, so success has to be read back rather than believed.
			name:   "the change was accepted but did not stick",
			apply:  func(sysproxy.State) error { return nil },
			verify: func(sysproxy.State) error { return errors.New("Wi-Fi did not stick") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
			var notices []string
			app.emitHook = func(name string, payload any) {
				if name == "runtime:notice" {
					notices = append(notices, payload.(string))
				}
			}
			original := sysproxy.State{Enabled: false}
			if err := app.writeSystemProxyBackup(original); err != nil {
				t.Fatal(err)
			}
			// The machine is still pointed at the proxy, which is what makes
			// this a restore that has to happen rather than one already done.
			defer swapSystemProxyCalls(t,
				func() (sysproxy.State, error) {
					return sysproxy.State{Enabled: true, Server: "127.0.0.1:2080"}, nil
				},
				tc.apply, tc.verify)()

			app.restoreSystemProxy()

			if _, ok := app.readSystemProxyBackup(); !ok {
				t.Fatal("the backup was deleted, so nothing can ever put these settings back")
			}
			if !app.state.Runtime.SystemProxyStranded {
				t.Fatal("the machine is still pointed at a stopped proxy and the state does not say so")
			}
			if !app.state.Runtime.SystemProxy {
				t.Fatal("the proxy is still set on the machine, so the state must not claim otherwise")
			}
			if len(notices) == 0 {
				t.Fatal("a user whose network has stopped working was told nothing")
			}
		})
	}
}

// The ordinary case, which has to keep working: the settings go back, they read
// back as gone, and the record of them is no longer needed.
func TestConfirmedRestoreClearsTheBackupAndTheWarning(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	app.state.Runtime.SystemProxy = true
	app.state.Runtime.SystemProxyStranded = true
	if err := app.writeSystemProxyBackup(sysproxy.State{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	defer swapSystemProxyCalls(t,
		func() (sysproxy.State, error) {
			return sysproxy.State{Enabled: true, Server: "127.0.0.1:2080"}, nil
		},
		func(sysproxy.State) error { return nil },
		func(sysproxy.State) error { return nil },
	)()

	app.restoreSystemProxy()

	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("a confirmed restore has nothing left to put back, so the backup should be gone")
	}
	if app.state.Runtime.SystemProxy || app.state.Runtime.SystemProxyStranded {
		t.Fatal("the machine was given back, so neither flag should still be set")
	}
}

// swapSystemProxyCalls puts test doubles in front of the machine and returns the
// function that puts the real ones back. A nil double keeps the current one.
func swapSystemProxyCalls(
	t *testing.T,
	current func() (sysproxy.State, error),
	apply func(sysproxy.State) error,
	verify func(sysproxy.State) error,
) func() {
	t.Helper()
	previousCurrent, previousApply, previousVerify := systemProxyCurrent, systemProxyApply, systemProxyVerify
	if current != nil {
		systemProxyCurrent = current
	}
	if apply != nil {
		systemProxyApply = apply
	}
	if verify != nil {
		systemProxyVerify = verify
	}
	return func() {
		systemProxyCurrent, systemProxyApply, systemProxyVerify = previousCurrent, previousApply, previousVerify
	}
}

// A machine that already holds what the backup asks for needs nothing done to
// it, and must not be asked to approve doing it.
//
// This is what makes a wrongly reported failure cost nothing. On macOS every
// attempt costs an administrator prompt, so without this a machine that was
// never wrong would be asked to approve putting back settings it already has,
// at every launch, forever.
func TestRestoringAMachineThatIsAlreadyCorrectAsksForNothing(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	app.state.Runtime.SystemProxy = true
	app.state.Runtime.SystemProxyStranded = true

	original := sysproxy.State{Enabled: false}
	if err := app.writeSystemProxyBackup(original); err != nil {
		t.Fatal(err)
	}

	applied := false
	defer swapSystemProxyCalls(t,
		// The machine is already off, which is what the backup asks for.
		func() (sysproxy.State, error) {
			return sysproxy.State{Enabled: false, Server: "127.0.0.1:2080"}, nil
		},
		func(sysproxy.State) error { applied = true; return nil },
		func(sysproxy.State) error { return nil },
	)()

	app.restoreSystemProxy()

	if applied {
		t.Fatal("the machine was already correct, so nothing should have been applied to it")
	}
	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("with nothing left to put back, the backup should be gone")
	}
	if app.state.Runtime.SystemProxyStranded {
		t.Fatal("a machine that is correct is not stranded, and the warning should have cleared itself")
	}
}

// But a machine that is genuinely still pointed at the stopped proxy is put
// back, rather than being waved through by the check above.
func TestRestoringAMachineStillPointedAtTheProxyStillActs(t *testing.T) {
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	if err := app.writeSystemProxyBackup(sysproxy.State{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	applied := false
	defer swapSystemProxyCalls(t,
		func() (sysproxy.State, error) {
			return sysproxy.State{Enabled: true, Server: "127.0.0.1:2080"}, nil
		},
		func(sysproxy.State) error { applied = true; return nil },
		func(sysproxy.State) error { return nil },
	)()

	app.restoreSystemProxy()

	if !applied {
		t.Fatal("the machine was still pointed at the proxy and should have been put back")
	}
}

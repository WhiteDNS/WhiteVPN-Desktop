package main

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/sysproxy"
)

// fakeProxyStore is an operating system with no operating system in it: two
// backends whose states live in a map, so the whole capture/commit/restore
// cycle can be proven on any development machine.
type fakeProxyStore struct {
	targets []sysproxy.Target
	states  map[string]sysproxy.State

	// failWrite lists which write attempt (1-based) fails per target; a
	// rollback is just another write.
	failWrite map[string][]int
	attempts  map[string]int

	// onWrite observes every write, in order.
	onWrite func(id string)
}

func newFakeProxyStore(ids ...string) *fakeProxyStore {
	s := &fakeProxyStore{
		states:    map[string]sysproxy.State{},
		failWrite: map[string][]int{},
		attempts:  map[string]int{},
	}
	for _, id := range ids {
		s.targets = append(s.targets, sysproxy.Target{ID: id, Kind: "fake"})
		s.states[id] = sysproxy.State{Enabled: false, Server: "old." + id + ":9"}
	}
	return s
}

func (s *fakeProxyStore) Targets() ([]sysproxy.Target, error) { return s.targets, nil }

func (s *fakeProxyStore) Read(t sysproxy.Target) (sysproxy.State, error) {
	return s.states[t.ID], nil
}

func (s *fakeProxyStore) Write(t sysproxy.Target, state sysproxy.State) error {
	s.attempts[t.ID]++
	for _, n := range s.failWrite[t.ID] {
		if n == s.attempts[t.ID] {
			return errors.New("write refused")
		}
	}
	s.states[t.ID] = state
	if s.onWrite != nil {
		s.onWrite(t.ID)
	}
	return nil
}

func (s *fakeProxyStore) Check(t sysproxy.Target, want sysproxy.State) error { return nil }

func installFakeStore(t *testing.T, store *fakeProxyStore) {
	t.Helper()
	prevStore, prevTargets := systemProxyStore, systemProxyTargets
	systemProxyStore = func() sysproxy.Store { return store }
	systemProxyTargets = func() ([]sysproxy.Target, error) { return store.Targets() }
	t.Cleanup(func() {
		systemProxyStore, systemProxyTargets = prevStore, prevTargets
	})
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	app := &App{state: model.DefaultAppState(), configDir: t.TempDir()}
	return app
}

// The backup exists so that a crash is survivable: the machine's proxy has to
// go back to what it was, and the only record of what it was is this file.
func TestSystemProxyBackupSurvivesToBeRestored(t *testing.T) {
	app := newTestApp(t)

	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("a fresh directory holds no backup, so nothing should be restored")
	}

	want := sysproxy.Snapshot{
		Version:  sysproxy.SnapshotVersion,
		Platform: "test",
		Targets:  map[string]sysproxy.State{"gnome": {Enabled: true, Server: "127.0.0.1:10808"}},
		Changed:  []string{"gnome"},
	}
	if err := app.writeSystemProxyBackup(want); err != nil {
		t.Fatal(err)
	}
	got, ok := app.readSystemProxyBackup()
	if !ok || !got.Targets["gnome"].SameAs(want.Targets["gnome"]) || !slices.Equal(got.Changed, want.Changed) {
		t.Fatalf("the backup did not survive: got %#v, want %#v", got, want)
	}
}

// A file that cannot be read is worse than none: kept, it would have the app
// trying to restore something it cannot understand on every start, forever.
func TestUnreadableSystemProxyBackupIsDiscarded(t *testing.T) {
	app := newTestApp(t)
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
	app := newTestApp(t)
	store := newFakeProxyStore("gnome")
	installFakeStore(t, store)
	app.state.Runtime.SystemProxy = true

	app.restoreSystemProxy()
	if !app.state.Runtime.SystemProxy {
		t.Fatal("with no backup there is nothing to restore, and nothing to report")
	}
	for id, state := range store.states {
		if !state.SameAs(sysproxy.State{Enabled: false, Server: "old." + id + ":9"}) {
			t.Fatalf("%s was touched by a restore that had no backup: %#v", id, state)
		}
	}
}

// The first format stored one State for the whole machine and applied it
// everywhere. Migrating assigns that state to every target present today —
// exactly what the old restore did — and rewrites the file natively.
func TestLegacySingleStateBackupMigratesToPerTarget(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("gnome", "kde6")
	installFakeStore(t, store)

	legacy := sysproxy.State{Enabled: true, Server: "127.0.0.1:9999", Override: "localhost"}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.systemProxyBackupPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got, ok := app.readSystemProxyBackup()
	if !ok {
		t.Fatal("a legacy backup must still restore")
	}
	if got.Version != sysproxy.SnapshotVersion {
		t.Fatalf("migrated snapshot should carry the current version, got %d", got.Version)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("legacy state should apply to every present target: %+v", got.Targets)
	}
	for _, id := range []string{"gnome", "kde6"} {
		if !got.Targets[id].SameAs(legacy) {
			t.Fatalf("%s did not inherit the legacy state: %#v", id, got.Targets[id])
		}
	}
	if !slices.Equal(got.Changed, []string{"gnome", "kde6"}) {
		t.Fatalf("migration records everything as changed: %v", got.Changed)
	}

	// The file was rewritten through, so the next start reads v2 without ever
	// knowing the old format existed.
	var onDisk sysproxy.Snapshot
	raw, err = os.ReadFile(app.systemProxyBackupPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil || onDisk.Version != sysproxy.SnapshotVersion {
		t.Fatalf("the migrated file should be native v2 now: %#v (%v)", onDisk, err)
	}
}

// When the machine's targets cannot even be listed, the legacy state cannot be
// mapped anywhere — and a backup nobody can act on is discarded rather than
// carried forever.
func TestLegacyMigrationWithoutListableTargetsDiscards(t *testing.T) {
	app := newTestApp(t)
	prev := systemProxyTargets
	systemProxyTargets = func() ([]sysproxy.Target, error) { return nil, errors.New("no desktop") }
	t.Cleanup(func() { systemProxyTargets = prev })

	raw, _ := json.Marshal(sysproxy.State{Enabled: true, Server: "x:1"})
	if err := os.WriteFile(app.systemProxyBackupPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("nothing can be restored from an unmappable backup")
	}
	if _, err := os.Stat(app.systemProxyBackupPath()); !os.IsNotExist(err) {
		t.Fatal("an unmappable backup should be discarded")
	}
}

// The record of what was there reaches disk before the first change. Proven by
// looking at the file from inside the first write.
func TestCaptureWritesBackupBeforeChangingAnything(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("gnome", "kde6")
	installFakeStore(t, store)
	first := true
	store.onWrite = func(string) {
		if !first {
			return
		}
		first = false
		if _, err := os.Stat(app.systemProxyBackupPath()); err != nil {
			t.Fatalf("the backup must exist before the first change, got %v", err)
		}
	}

	if err := app.captureSystemProxy(2080); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureChangesEveryTargetAndPersistsChangedList(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("gnome", "kde6")
	installFakeStore(t, store)

	if err := app.captureSystemProxy(2080); err != nil {
		t.Fatal(err)
	}
	for id, state := range store.states {
		if !state.SameAs(sysproxy.State{Enabled: true, Server: "127.0.0.1:2080", Override: sysproxy.DefaultBypass}) {
			t.Fatalf("%s does not point at the proxy: %#v", id, state)
		}
	}
	snap, ok := app.readSystemProxyBackup()
	if !ok {
		t.Fatal("a completed capture keeps its snapshot until disconnect")
	}
	if !slices.Equal(snap.Changed, []string{"gnome", "kde6"}) {
		t.Fatalf("the snapshot must list exactly what changed: %v", snap.Changed)
	}
	if !snap.Targets["gnome"].SameAs(sysproxy.State{Enabled: false, Server: "old.gnome:9"}) {
		t.Fatalf("the captured original was lost: %#v", snap.Targets["gnome"])
	}
	if !app.state.Runtime.SystemProxy {
		t.Fatal("the runtime flag should say the machine's proxy is pointed here")
	}
}

func TestFailedCaptureRollsBackAndLeavesNoFile(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("gnome", "kde6")
	installFakeStore(t, store)
	store.failWrite["kde6"] = []int{1} // takes nothing, so rollback has one job

	err := app.captureSystemProxy(2080)
	if err == nil {
		t.Fatal("a refusing backend fails the capture")
	}
	if !store.states["gnome"].SameAs(sysproxy.State{Enabled: false, Server: "old.gnome:9"}) {
		t.Fatalf("the healthy backend was left pointing at the proxy: %#v", store.states["gnome"])
	}
	if _, ok := app.readSystemProxyBackup(); ok {
		t.Fatal("nothing needs restoring, so no file should remain")
	}
	if app.state.Runtime.SystemProxy {
		t.Fatal("a failed capture must not claim the proxy was set")
	}
}

// A backend that took the change but refuses to give it back stays recorded:
// dropping it would leave the machine pointed at a dead port with nobody
// remembering why.
func TestPartialRollbackKeepsFileListingWhatStillOwes(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("a", "b")
	installFakeStore(t, store)
	store.failWrite["b"] = []int{1} // refuses outright
	store.failWrite["a"] = []int{2} // takes the change, refuses the rollback

	err := app.captureSystemProxy(2080)
	var te *sysproxy.TransactionError
	if !errors.As(err, &te) || !slices.Equal(te.Unrolled, []string{"a"}) {
		t.Fatalf("expected a reported unrolled target, got %v", err)
	}
	snap, ok := app.readSystemProxyBackup()
	if !ok {
		t.Fatal("the file must survive while a target still holds our values")
	}
	if !slices.Equal(snap.Changed, []string{"a"}) {
		t.Fatalf("the snapshot must list what still owes: %v", snap.Changed)
	}
	if !store.states["a"].SameAs(sysproxy.State{Enabled: true, Server: "127.0.0.1:2080", Override: sysproxy.DefaultBypass}) {
		t.Fatalf("a should still hold our values: %#v", store.states["a"])
	}
}

// The startup case: a crash mid-connect leaves a snapshot whose Changed list is
// exactly what was touched. Restoring puts each back independently.
func TestRestorePutsEachTargetBackAndRemovesTheFile(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("gnome", "kde6")
	installFakeStore(t, store)
	originalGnome := sysproxy.State{Enabled: true, Server: "corp-proxy:3128"}
	originalKDE := sysproxy.State{Enabled: false}
	snap := sysproxy.Snapshot{
		Version: sysproxy.SnapshotVersion,
		Targets: map[string]sysproxy.State{"gnome": originalGnome, "kde6": originalKDE},
		Changed: []string{"gnome", "kde6"},
	}
	if err := app.writeSystemProxyBackup(snap); err != nil {
		t.Fatal(err)
	}
	app.state.Runtime.SystemProxy = true

	app.restoreSystemProxy()

	if !store.states["gnome"].SameAs(originalGnome) {
		t.Fatalf("gnome restored wrong: %#v", store.states["gnome"])
	}
	if !store.states["kde6"].SameAs(originalKDE) {
		t.Fatalf("kde6 restored wrong: %#v", store.states["kde6"])
	}
	if _, err := os.Stat(app.systemProxyBackupPath()); !os.IsNotExist(err) {
		t.Fatal("a finished restore removes its backup")
	}
	if app.state.Runtime.SystemProxy {
		t.Fatal("restore clears the runtime flag")
	}
}

// One refusing backend must not keep another's original state from going back.
func TestRestoreKeepsGoingWhenOneBackendRefuses(t *testing.T) {
	app := newTestApp(t)
	store := newFakeProxyStore("a", "b")
	installFakeStore(t, store)
	snap := sysproxy.Snapshot{
		Version: sysproxy.SnapshotVersion,
		Targets: map[string]sysproxy.State{"a": {Enabled: false}, "b": {Enabled: false}},
		Changed: []string{"a", "b"},
	}
	if err := app.writeSystemProxyBackup(snap); err != nil {
		t.Fatal(err)
	}
	store.failWrite["a"] = []int{1}

	app.restoreSystemProxy()

	if !store.states["b"].SameAs(sysproxy.State{Enabled: false}) {
		t.Fatalf("b should have been restored despite a refusing: %#v", store.states["b"])
	}
	remaining, ok := app.readSystemProxyBackup()
	if !ok || !slices.Equal(remaining.Changed, []string{"a"}) {
		t.Fatalf("only the unfinished target should stay listed: %v", remaining.Changed)
	}
}

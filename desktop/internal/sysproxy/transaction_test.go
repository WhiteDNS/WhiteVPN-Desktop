package sysproxy

import (
	"errors"
	"slices"
	"testing"
)

// fakeStore is a store with no operating system in it, which is the point: the
// transaction has to be provable without GNOME, KDE or a network service in
// front of it.
type fakeStore struct {
	targets []Target
	states  map[string]State

	// failWrite lists, per target, which write attempt (1-based) fails. A
	// rollback is just another write, so "first write works, second fails" is
	// how a backend that accepted the change but refuses to give it up is
	// modelled.
	failWrite map[string][]int
	failCheck map[string]bool

	attempts map[string]int
	onChange [][]string
}

func newFakeStore(ids ...string) *fakeStore {
	s := &fakeStore{
		states:    map[string]State{},
		failWrite: map[string][]int{},
		failCheck: map[string]bool{},
		attempts:  map[string]int{},
	}
	for _, id := range ids {
		s.targets = append(s.targets, Target{ID: id, Kind: "fake"})
		s.states[id] = State{Enabled: false, Server: "old." + id + ":1"}
	}
	return s
}

func (s *fakeStore) Targets() ([]Target, error) { return s.targets, nil }

func (s *fakeStore) Read(t Target) (State, error) { return s.states[t.ID], nil }

func (s *fakeStore) Write(t Target, state State) error {
	s.attempts[t.ID]++
	for _, n := range s.failWrite[t.ID] {
		if n == s.attempts[t.ID] {
			return errors.New("write refused")
		}
	}
	s.states[t.ID] = state
	return nil
}

func (s *fakeStore) Check(t Target, want State) error {
	if s.failCheck[t.ID] {
		return errors.New("readback disagrees")
	}
	return nil
}

func (s *fakeStore) record(changed []string) {
	s.onChange = append(s.onChange, append([]string(nil), changed...))
}

func TestCaptureReadsEveryTarget(t *testing.T) {
	store := newFakeStore("gnome", "kde6")
	snap, err := Capture(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Targets) != 2 {
		t.Fatalf("captured %+v", snap.Targets)
	}
	if snap.Version != SnapshotVersion || len(snap.Changed) != 0 {
		t.Fatalf("fresh snapshot must be versioned and record nothing changed: %+v", snap)
	}
}

func TestCaptureWithNothingReadableIsUnsupported(t *testing.T) {
	store := newFakeStore()
	if _, err := Capture(store); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

func TestCommitChangesEveryTargetAndReportsProgress(t *testing.T) {
	store := newFakeStore("gnome", "kde6")
	snap, err := Capture(store)
	if err != nil {
		t.Fatal(err)
	}
	want := State{Enabled: true, Server: "127.0.0.1:2080"}
	changed, err := Commit(store, snap, want, store.record)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(changed, []string{"gnome", "kde6"}) {
		t.Fatalf("changed = %v", changed)
	}
	for _, id := range changed {
		if got := store.states[id]; !got.SameAs(want) {
			t.Fatalf("%s holds %#v", id, got)
		}
	}
	// Progress is reported after every change, growing list first — this is what
	// makes an on-disk copy true at every instant of the transaction.
	if len(store.onChange) < 2 ||
		!slices.Equal(store.onChange[0], []string{"gnome"}) ||
		!slices.Equal(store.onChange[1], []string{"gnome", "kde6"}) {
		t.Fatalf("progress was not reported per change: %v", store.onChange)
	}
}

func TestCommitRollsBackEverythingWhenOneTargetFails(t *testing.T) {
	store := newFakeStore("a", "b", "c")
	snap, _ := Capture(store)
	store.failWrite["c"] = []int{1}

	want := State{Enabled: true, Server: "127.0.0.1:2080"}
	_, err := Commit(store, snap, want, nil)
	if err == nil {
		t.Fatal("a refusing target must fail the transaction")
	}
	var te *TransactionError
	if errors.As(err, &te) {
		t.Fatalf("rollback succeeded, so this is a plain failure: %#v", te)
	}
	for _, id := range []string{"a", "b"} {
		if !store.states[id].SameAs(snap.Targets[id]) {
			t.Fatalf("%s was not rolled back: holds %#v, want %#v", id, store.states[id], snap.Targets[id])
		}
	}
}

// A backend whose readback disagrees is exactly as dangerous as one that
// refused: it says the setting took when it did not. It gets the same rollback,
// and — the acceptance case — the other backend that worked does not get dragged
// into failing with it.
func TestCommitRollsBackWhenVerificationFails(t *testing.T) {
	store := newFakeStore("gnome", "kde6")
	snap, _ := Capture(store)
	store.failCheck["kde6"] = true

	_, err := Commit(store, snap, State{Enabled: true, Server: "127.0.0.1:2080"}, nil)
	if err == nil {
		t.Fatal("a failed readback must fail the transaction")
	}
	if !store.states["gnome"].SameAs(snap.Targets["gnome"]) {
		t.Fatalf("the healthy backend was left changed: %#v", store.states["gnome"])
	}
}

func TestCommitKeepsOwedRestoresInError(t *testing.T) {
	store := newFakeStore("a", "b")
	snap, _ := Capture(store)
	// a takes the change but refuses to give it back; b refuses outright.
	store.failWrite["a"] = []int{2}
	store.failWrite["b"] = []int{1}

	_, err := Commit(store, snap, State{Enabled: true, Server: "x:1"}, nil)
	var te *TransactionError
	if !errors.As(err, &te) || !slices.Equal(te.Unrolled, []string{"a"}) {
		t.Fatalf("expected a to be reported unrolled, got %#v", err)
	}
}

func TestRestorePutsBackExactlyWhatChanged(t *testing.T) {
	store := newFakeStore("gnome", "kde6", "untouched")
	snap, _ := Capture(store)
	snap.Changed = []string{"gnome", "kde6"}
	before := store.states["untouched"]

	if err := Restore(store, snap, nil); err != nil {
		t.Fatal(err)
	}
	if !store.states["untouched"].SameAs(before) {
		t.Fatal("restore reached a backend it never changed")
	}
	for _, id := range snap.Changed {
		if !store.states[id].SameAs(snap.Targets[id]) {
			t.Fatalf("%s restored wrong: %#v", id, store.states[id])
		}
	}
}

func TestRestoreTreatsVanishedTargetAsSettled(t *testing.T) {
	store := newFakeStore("Wi-Fi")
	snap := Snapshot{
		Version: SnapshotVersion,
		Targets: map[string]State{"Wi-Fi": {Enabled: false}, "Ethernet": {Enabled: false}},
		Changed: []string{"Wi-Fi", "Ethernet"},
	}
	// Ethernet was unplugged while connected. There is nowhere to put its
	// settings back; demanding success forever would keep the backup alive for
	// eternity.
	if err := Restore(store, snap, nil); err != nil {
		t.Fatalf("a vanished target must not block restore: %v", err)
	}
}

func TestRestoreKeepsGoingAfterOneFailure(t *testing.T) {
	store := newFakeStore("a", "b")
	snap, _ := Capture(store)
	snap.Changed = []string{"a", "b"}
	store.failWrite["a"] = []int{1}

	err := Restore(store, snap, nil)
	if err == nil {
		t.Fatal("a failed restore must be reported")
	}
	if !store.states["b"].SameAs(snap.Targets["b"]) {
		t.Fatal("one failing target must not stop the others being put back")
	}
}

func TestRestoreWithoutRecordedStateReportsIt(t *testing.T) {
	store := newFakeStore("a")
	snap := Snapshot{Version: SnapshotVersion, Changed: []string{"a"}}
	if err := Restore(store, snap, nil); err == nil {
		t.Fatal("restoring without a recorded original state must say so")
	}
}

// A snapshot written twice by a buggy older build could list one target two
// times; restoring it must still finish instead of leaving the backup file
// alive forever behind an id that never settles.
func TestRestoreSurvivesDuplicateChangedEntries(t *testing.T) {
	store := newFakeStore("a")
	snap := Snapshot{
		Version: SnapshotVersion,
		Targets: map[string]State{"a": {Enabled: false}},
		Changed: []string{"a", "a", "a"},
	}
	if err := Restore(store, snap, nil); err != nil {
		t.Fatalf("duplicates must not block restore: %v", err)
	}
}

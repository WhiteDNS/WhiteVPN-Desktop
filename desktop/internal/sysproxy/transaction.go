package sysproxy

import (
	"fmt"
	"sort"
	"strings"
)

// The transaction that keeps a proxy change from becoming a half-change.
//
// The order is the whole point. Every state is read before anything is written;
// each target is verified after its own write; and a failure anywhere rolls
// back everything already done, in reverse. The caller is told after every
// single change so it can keep its on-disk record true — if the process dies
// mid-transaction, that record says exactly which targets were touched and
// holds exactly what they were.

// Capture reads every target the store offers, and returns them as a snapshot
// nothing has been changed to match yet.
//
// A target whose read fails is left out rather than guessed at: writing blind to
// a backend that cannot be read is writing somewhere that cannot be restored.
func Capture(store Store) (Snapshot, error) {
	targets, err := store.Targets()
	if err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{Version: SnapshotVersion, Targets: map[string]State{}}
	var firstErr error
	for _, t := range targets {
		state, err := store.Read(t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		snap.Targets[t.ID] = state
	}
	if len(snap.Targets) == 0 {
		if firstErr != nil {
			return Snapshot{}, fmt.Errorf("sysproxy: no proxy setting could be read: %w", firstErr)
		}
		return Snapshot{}, ErrUnsupported
	}
	return snap, nil
}

// TransactionError reports a failed transaction whose automatic rollback could
// not finish. Unrolled names the targets still holding this app's values; their
// original states are in the snapshot, which the caller must now keep until
// they are restored — usually by trying again at startup.
type TransactionError struct {
	Cause    error
	Unrolled []string
}

func (e *TransactionError) Error() string {
	if len(e.Unrolled) == 0 {
		return e.Cause.Error()
	}
	return fmt.Sprintf("%v (could not put back: %s)", e.Cause, strings.Join(e.Unrolled, ", "))
}

func (e *TransactionError) Unwrap() error { return e.Cause }

// Commit writes want to every captured target and verifies each write.
//
// It returns the targets that were changed and verified. onChange fires after
// every single change with the list so far, so the caller can persist the
// growing record — the difference between a crash-safe backup and a hopeful
// one. On failure it rolls back what it changed; targets whose rollback also
// failed come back inside a *TransactionError and stay listed as changed,
// because giving up on them would leave the machine pointed at a dead port
// with nobody remembering why.
func Commit(store Store, snap Snapshot, want State, onChange func(changed []string)) ([]string, error) {
	report := func(changed []string) {
		if onChange != nil {
			onChange(append([]string(nil), changed...))
		}
	}
	// Asked once rather than per target: on Linux every Targets() call probes
	// the desktop backends by running their tools, and a transaction that
	// spawned a dozen processes just to remember what exists would be its own
	// kind of slowness.
	present := targetIndex(store)

	var changed []string
	for _, id := range orderedIDs(snap) {
		t, ok := present[id]
		if !ok {
			// Gone between capture and commit: nothing to change, so nothing to
			// roll back later either.
			continue
		}
		if err := store.Write(t, want); err != nil {
			return nil, rollback(store, present, snap, changed, report,
				fmt.Errorf("sysproxy: set %s: %w", id, err))
		}
		changed = append(changed, id)
		report(changed)
		if err := store.Check(t, want); err != nil {
			return nil, rollback(store, present, snap, changed, report,
				fmt.Errorf("sysproxy: %s did not keep the settings: %w", id, err))
		}
	}
	return changed, nil
}

// rollback puts every changed target back, last first, reporting after each one.
// What cannot be put back is reported as unrolled rather than dropped.
func rollback(store Store, present map[string]Target, snap Snapshot, changed []string, report func([]string), cause error) error {
	var unrolled []string
	for i := len(changed) - 1; i >= 0; i-- {
		id := changed[i]
		t, ok := present[id]
		if !ok {
			continue
		}
		if err := store.Write(t, snap.Targets[id]); err != nil {
			unrolled = append(unrolled, changed[:i+1]...)
			break
		}
		report(changed[:i])
	}
	if len(unrolled) > 0 {
		sort.Strings(unrolled)
		return &TransactionError{Cause: cause, Unrolled: unrolled}
	}
	return cause
}

// Restore puts every changed target back to its captured state, one at a time.
//
// It is safe to call repeatedly, including at startup after a crash. Targets no
// longer present on the machine count as restored: there is nowhere left to put
// anything back. onProgress is called after each settlement with the ids still
// owed, so a caller keeping the record on disk can persist exactly what remains.
// The error, when there is one, names what could not be restored — and the
// caller should hold onto the snapshot until Restore stops complaining.
func Restore(store Store, snap Snapshot, onProgress func(remaining []string)) error {
	present := targetIndex(store)
	// A duplicated id would be settled once and then haunt pending forever,
	// keeping the backup file alive for eternity — collapse repeats up front.
	var pending []string
	for _, id := range snap.Changed {
		if !containsString(pending, id) {
			pending = append(pending, id)
		}
	}
	settle := func(id string) {
		for i, have := range pending {
			if have == id {
				pending = append(pending[:i], pending[i+1:]...)
				break
			}
		}
		if onProgress != nil {
			onProgress(append([]string(nil), pending...))
		}
	}

	var problems []string
	for _, id := range append([]string(nil), pending...) {
		state, ok := snap.Targets[id]
		if !ok {
			// A snapshot without the target's original state cannot restore it;
			// say so instead of quietly pretending it happened.
			problems = append(problems, fmt.Sprintf("%s: no recorded state", id))
			continue
		}
		t, ok := present[id]
		if !ok {
			settle(id)
			continue
		}
		if err := store.Write(t, state); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		settle(id)
	}
	if len(pending) == 0 && len(problems) == 0 {
		return nil
	}
	sort.Strings(pending)
	detail := strings.Join(problems, "; ")
	if detail == "" {
		detail = "the settings are no longer reachable on this machine"
	}
	return fmt.Errorf("sysproxy: could not restore (%d left): %s", len(pending), detail)
}

func orderedIDs(snap Snapshot) []string {
	ids := make([]string, 0, len(snap.Targets))
	for id := range snap.Targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// targetIndex lists what exists now, once. A store that cannot answer gets an
// empty index, which every caller treats as "nothing is reachable" and fails
// closed.
func targetIndex(store Store) map[string]Target {
	index := make(map[string]Target)
	targets, err := store.Targets()
	if err != nil {
		return index
	}
	for _, t := range targets {
		index[t.ID] = t
	}
	return index
}

func containsString(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

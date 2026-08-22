package sysproxy

import "errors"

// A proxy setting is not one thing on every machine, and it is rarely one thing
// on any machine. Linux keeps GNOME's and KDE's side by side and both are worth
// writing; macOS keeps one per network service, because the service the user is
// on now is not the one they will be on in an hour; Windows has WinINET. What
// they share is that each place can be read, written and put back on its own,
// which is exactly what a crash-recovery file needs from it.
//
// So the unit of backup is a Target: one named place, captured before anything
// changes, restored after — independently of its neighbours, so one refusing
// backend never blocks another's recovery.

// Target is one independently restorable place a proxy setting lives.
type Target struct {
	// ID is stable for this machine: "wininet", "gnome", "kde6", "kde5", or a
	// macOS network service name such as "Wi-Fi". It is the key the snapshot
	// stores the target's original state under.
	ID string `json:"id"`
	// Kind says what sort of place it is ("wininet", "gnome", "kde",
	// "network-service"), for logs and for callers that treat them differently.
	Kind string `json:"kind"`
}

// SnapshotVersion is the on-disk backup format this build writes. The first
// format stored a single State with no version at all; readers detect it by the
// missing field and migrate.
const SnapshotVersion = 2

// Snapshot is the exact proxy state of every target this app is about to touch,
// captured before touching any of them.
//
// Changed lists the targets this app has actually changed so far. It grows as
// each target takes and shrinks as each is put back, because the value of the
// file is being true at the moment of a crash: whatever it says was changed is
// precisely what needs putting back, no more and no less.
type Snapshot struct {
	Version  int              `json:"version"`
	Platform string           `json:"platform"`
	Targets  map[string]State `json:"targets"`
	Changed  []string         `json:"changed,omitempty"`
}

// Store is the platform's set of proxy settings, reached one target at a time.
// Each operating system supplies its own; the transaction logic above them is
// shared, which is why it can be tested without any of them.
type Store interface {
	// Targets lists the places that exist and answered right now. One that
	// cannot be probed — no session behind gsettings, a network service that
	// went away — is simply absent.
	Targets() ([]Target, error)
	// Read reports what the target holds at this moment.
	Read(Target) (State, error)
	// Write puts a state in place.
	Write(Target, State) error
	// Check verifies a write took. Reading back beats assuming: another program
	// can be writing the same key.
	Check(Target, State) error
}

// ErrUnsupported is returned when nothing on this machine knows what a proxy
// setting is — a bare window manager, or a session with neither toolkit.
var ErrUnsupported = errors.New("sysproxy: no desktop proxy setting found (this needs GNOME's gsettings or KDE's kwriteconfig)")

// ReadbackMismatch says a target holds something other than what was asked
// for. Named rather than formatted into text because callers tell these apart:
// a mismatch is a different sentence to a user than a command that failed.
type ReadbackMismatch struct {
	Target string
	Want   State
	Got    State
}

func (e *ReadbackMismatch) Error() string {
	return "sysproxy: " + e.Target + " did not keep the settings (wanted " +
		describeState(e.Want) + ", found " + describeState(e.Got) + ")"
}

func describeState(s State) string {
	if s.Enabled {
		return s.Server + " enabled"
	}
	return "disabled"
}

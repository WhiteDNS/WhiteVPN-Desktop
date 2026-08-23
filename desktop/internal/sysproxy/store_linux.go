//go:build linux

package sysproxy

// The store side of the Linux backends.
//
// What makes a backend real is not its executable being on PATH. A machine can
// have gsettings installed with no session behind it — a container, an SSH
// login, a display manager's greeter — and kwriteconfig5 without the
// kreadconfig5 that would put the setting back. So each backend is probed by
// asking it a question before it is trusted with a change, and one that does
// not answer simply is not offered as a target: writing to it would be writing
// somewhere that cannot be read back or restored.

import "os/exec"

// backend is one place Linux keeps the setting, once it has answered for
// itself. name doubles as the target id; reader and writer are separate because
// KDE splits them and GNOME does not.
type backend struct {
	name   string
	writer string
	reader string
}

// probeRun runs one command and reports whether it worked. It is a variable so
// a test can stand in for the desktop session this machine may not have.
var probeRun = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// findBinary reports whether an executable is on PATH. Variable for the same
// reason: a test has no KDE here.
var findBinary = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// usableBackends lists the backends that exist AND answered.
//
// KDE is probed through its reader rather than only its writer, because the
// writer alone can put values where nothing reads them — and because the
// reader is what a restore needs. An explicit default keeps the read honest on
// a machine that has the tools but has never opened KDE's proxy settings: no
// key yet must not read as a broken backend.
//
// KDE 6 first: a machine with both has moved on, and writing the old one there
// configures a file nothing reads.
func usableBackends() []backend {
	candidates := []backend{
		{name: "gnome", writer: gsettingsBinary, reader: gsettingsBinary},
		{name: "kde6", writer: "kwriteconfig6", reader: "kreadconfig6"},
		{name: "kde5", writer: "kwriteconfig5", reader: "kreadconfig5"},
	}
	found := make([]backend, 0, len(candidates))
	for _, b := range candidates {
		if !findBinary(b.writer) || !findBinary(b.reader) {
			continue
		}
		if !backendAnswers(b) {
			continue
		}
		found = append(found, b)
	}
	return found
}

func backendAnswers(b backend) bool {
	switch b.name {
	case "gnome":
		// Reading the schema proves both that it is installed and that a
		// session is behind it; either missing and the write would fail too.
		return probeRun(gsettingsBinary, "get", gnomeProxySchema, "mode") == nil
	default:
		return probeRun(b.reader, "--file", kdeProxyConfigFile,
			"--group", kdeProxyGroup, "--key", "ProxyType", "--default", "unset") == nil
	}
}

// BackendNames lists the desktop backends that exist AND answered, by target
// id ("gnome", "kde6", "kde5"). It is how capability reporting describes this
// machine without running a transaction.
func BackendNames() []string {
	backends := usableBackends()
	names := make([]string, 0, len(backends))
	for _, b := range backends {
		names = append(names, b.name)
	}
	return names
}

// linuxStore reaches every answering backend as an independent target.
type linuxStore struct{}

// SystemStore is this platform's proxy-setting store.
func SystemStore() Store { return linuxStore{} }

func (linuxStore) Targets() ([]Target, error) {
	backends := usableBackends()
	if len(backends) == 0 {
		return nil, ErrUnsupported
	}
	targets := make([]Target, 0, len(backends))
	for _, b := range backends {
		targets = append(targets, Target{ID: b.name, Kind: kindOf(b.name)})
	}
	return targets, nil
}

func kindOf(name string) string {
	if name == "gnome" {
		return "gnome"
	}
	return "kde"
}

func (linuxStore) Read(t Target) (State, error) {
	b, err := backendByID(t.ID)
	if err != nil {
		return State{}, err
	}
	return readBackend(*b)
}

func (linuxStore) Write(t Target, state State) error {
	b, err := backendByID(t.ID)
	if err != nil {
		return err
	}
	return writeBackend(*b, state)
}

func (linuxStore) Check(t Target, want State) error {
	got, err := linuxStore{}.Read(t)
	if err != nil {
		return err
	}
	if !got.SameAs(want) {
		return &ReadbackMismatch{Target: t.ID, Want: want, Got: got}
	}
	return nil
}

func backendByID(id string) (*backend, error) {
	for _, b := range usableBackends() {
		if b.name == id {
			return &b, nil
		}
	}
	return nil, ErrUnsupported
}

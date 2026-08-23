//go:build windows

package sysproxy

// Windows has exactly one place: the per-user WinINET settings. The store is
// thin for that reason — its value is that the transaction above it treats the
// machine's single setting the same way Linux treats five backends, so the
// backup on disk has one format everywhere.

type wininetStore struct{}

// SystemStore is this platform's proxy-setting store.
func SystemStore() Store { return wininetStore{} }

func (wininetStore) Targets() ([]Target, error) {
	return []Target{{ID: "wininet", Kind: "wininet"}}, nil
}

func (wininetStore) Read(Target) (State, error) { return Current() }

func (wininetStore) Write(_ Target, state State) error { return Apply(state) }

func (wininetStore) Check(_ Target, want State) error { return Verify(want) }

package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/securestore"
)

const privateStateSchema = "whitevpn.desktop.private-state"

// Keep disk serialization independent of any future public AppState marshaler.
type privateAppState model.AppState
type privateStateEnvelope struct {
	Schema  string          `json:"schema"`
	Version int             `json:"version"`
	State   privateAppState `json:"state"`
}

type stateSnapshot interface {
	Read() ([]byte, error)
	Write([]byte) error
}
type protectedState struct {
	vault, recovery stateSnapshot
	protector       securestore.Protector
	ready           bool
}

func newProtectedStore(legacyPath string, protector securestore.Protector) *Store {
	dir := filepath.Join(filepath.Dir(legacyPath), "state-v2")
	return &Store{path: legacyPath, protected: &protectedState{
		protector: protector,
		vault:     securestore.New(filepath.Join(dir, "desktop-state.vault"), protector),
		recovery:  securestore.New(filepath.Join(dir, "desktop-state-recovery.vault"), protector),
	}}
}

func (s *Store) IsProtected() bool { return s.protected != nil }

// HasStoredState must be called before Load, since a fresh Windows Load creates
// the initial encrypted checkpoint. Missing main + existing recovery is not a
// fresh install and must never import an old binary's state.
func (s *Store) HasStoredState() (bool, error) {
	paths := []string{s.path}
	if s.IsProtected() {
		dir := filepath.Join(filepath.Dir(s.path), "state-v2")
		paths = append(paths, filepath.Join(dir, "desktop-state.vault"), filepath.Join(dir, "desktop-state-recovery.vault"))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func encodePrivateState(state model.AppState) ([]byte, error) {
	state.Runtime = model.DefaultAppState().Runtime
	return json.Marshal(privateStateEnvelope{Schema: privateStateSchema, Version: 1, State: privateAppState(state)})
}

func decodePrivateState(raw []byte) (model.AppState, error) {
	var envelope privateStateEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Schema != privateStateSchema || envelope.Version != 1 {
		return model.AppState{}, securestore.ErrCorrupt
	}
	// Reject null/missing state instead of interpreting it as a fresh install.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if state := bytes.TrimSpace(fields["state"]); len(state) == 0 || state[0] != '{' {
		return model.AppState{}, securestore.ErrCorrupt
	}
	return model.AppState(envelope.State), nil
}

func (s *Store) loadProtectedLocked() (model.AppState, error) {
	s.protected.ready = false
	raw, err := s.protected.vault.Read()
	if errors.Is(err, os.ErrNotExist) {
		// A recovery checkpoint proves that this installation already migrated.
		// Keep it for explicit repair, never auto-restore stale credentials.
		checkpoint, recoveryErr := s.protected.recovery.Read()
		clear(checkpoint)
		if !errors.Is(recoveryErr, os.ErrNotExist) {
			return model.AppState{}, fmt.Errorf("private state is missing; preserve the encrypted recovery checkpoint for repair")
		}
		state := model.DefaultAppState()
		legacy, legacyErr := readLegacyStateBounded(s.path)
		if legacyErr == nil {
			defer clear(legacy)
			if json.Unmarshal(legacy, &state) != nil || len(bytes.TrimSpace(legacy)) == 0 || bytes.TrimSpace(legacy)[0] != '{' {
				return model.AppState{}, fmt.Errorf("legacy state is invalid; migration left the source unchanged")
			}
		} else if !errors.Is(legacyErr, os.ErrNotExist) {
			return model.AppState{}, legacyErr
		}
		state, _, err = s.prepareStateLocked(state, false)
		if err != nil {
			return model.AppState{}, err
		}
		raw, err = encodePrivateState(state)
		if err != nil {
			return model.AppState{}, err
		}
		if err = s.protected.vault.Write(raw); err != nil {
			clear(raw)
			return model.AppState{}, err
		}
	} else if err != nil {
		return model.AppState{}, err
	}
	defer clear(raw)
	state, err := decodePrivateState(raw)
	if err != nil {
		return model.AppState{}, err
	}
	// A checkpoint or plaintext cleanup failure keeps startup blocked. A later
	// Load resumes from the committed vault, including after a crash at this point.
	if err := s.finishProtectedMigrationLocked(raw); err != nil {
		return model.AppState{}, err
	}
	state, migrated, err := s.prepareStateLocked(state, false)
	if err != nil {
		return model.AppState{}, err
	}
	s.protected.ready = true
	if migrated {
		if err := s.writeProtectedLocked(state); err != nil {
			s.protected.ready = false
			return model.AppState{}, err
		}
	}
	return state, nil
}

func (s *Store) finishProtectedMigrationLocked(raw []byte) error {
	checkpoint, err := s.protected.recovery.Read()
	if errors.Is(err, os.ErrNotExist) {
		if err := s.protected.recovery.Write(raw); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		_, err = decodePrivateState(checkpoint)
		clear(checkpoint)
		if err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if base, ok := securestore.LegacyTemporaryBase(entry.Name()); ok && base == filepath.Base(s.path) {
			source := filepath.Join(filepath.Dir(s.path), entry.Name())
			destination := filepath.Join(filepath.Dir(s.path), "state-v2", "legacy-state-temporaries", entry.Name()+".vault")
			if err := securestore.ArchiveLegacyFile(source, destination, s.protected.protector); err != nil {
				return err
			}
		}
	}
	// This is only this application's legacy file, never WhiteDNS's import source.
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("encrypted state committed but legacy plaintext cleanup failed")
	}
	return nil
}

func (s *Store) writeProtectedLocked(state model.AppState) error {
	if !s.protected.ready {
		return fmt.Errorf("private state must load successfully before saving")
	}
	// Refuse to overwrite corruption or deletion that occurred after Load.
	// Reset must explicitly Load the fresh store before it can save again.
	old, err := s.protected.vault.Read()
	if err != nil {
		return err
	}
	defer clear(old)
	if _, err := decodePrivateState(old); err != nil {
		return err
	}
	// Validate recovery and finish any old-binary plaintext cleanup before the
	// new commit, so failure here cannot ambiguously commit the requested edit.
	if err := s.finishProtectedMigrationLocked(old); err != nil {
		return err
	}
	raw, err := encodePrivateState(state)
	if err != nil {
		return err
	}
	defer clear(raw)
	return s.protected.vault.Write(raw)
}

func readLegacyStateBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > securestore.MaxPlaintextBytes {
		return nil, fmt.Errorf("legacy state is not a supported regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, securestore.MaxPlaintextBytes+1))
	if len(raw) > securestore.MaxPlaintextBytes {
		clear(raw)
		return nil, fmt.Errorf("legacy state is too large")
	}
	return raw, err
}

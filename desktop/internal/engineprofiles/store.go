package engineprofiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/uuid"
	"whitevpn-desktop/internal/securestore"
)

var (
	ErrConflict = errors.New("profile changed; reopen the editor before saving")
	ErrNotFound = errors.New("engine profile was not found")
)

type SnapshotStore interface {
	Read() ([]byte, error)
	Write([]byte) error
}

type catalog struct {
	Schema   int       `json:"schema"`
	Profiles []Profile `json:"profiles"`
	Selected *RouteRef `json:"selected,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	disk  SnapshotStore
	state catalog
}

// Open never replaces an unreadable/corrupt vault with an empty catalog.
func Open(disk SnapshotStore) (*Store, error) {
	if disk == nil {
		return nil, securestore.ErrUnavailable
	}
	s := &Store{disk: disk, state: catalog{Schema: SchemaVersion, Profiles: []Profile{}}}
	raw, err := disk.Read()
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > securestore.MaxPlaintextBytes || !uniqueJSON(raw) || d.Decode(&s.state) != nil || d.Decode(new(any)) != io.EOF || s.state.Schema != SchemaVersion {
		return nil, securestore.ErrCorrupt
	}
	if len(s.state.Profiles) > MaxProfiles {
		return nil, securestore.ErrCorrupt
	}
	seen := map[string]bool{}
	for _, p := range s.state.Profiles {
		if p.Validate() != nil || p.Revision == 0 || p.Revision > (1<<53)-1 || seen[p.ID] {
			return nil, securestore.ErrCorrupt
		}
		seen[p.ID] = true
	}
	if s.state.Selected != nil && s.state.Selected.Validate() != nil {
		return nil, securestore.ErrCorrupt
	}
	// A missing selected profile remains unresolved. It must never choose another.
	return s, nil
}

func (s *Store) List() []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Summary, len(s.state.Profiles))
	for i, p := range s.state.Profiles {
		out[i] = p.Summary
	}
	return out
}

func (s *Store) ForEdit(id string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.state.Profiles {
		if p.ID == id {
			return p.Clone(), nil
		}
	}
	return Profile{}, ErrNotFound
}

func (s *Store) Save(input Profile) (Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := input.Defaults()
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	if p.Version == 0 {
		p.Version = SchemaVersion
	}
	if err := p.Validate(); err != nil {
		return Summary{}, err
	}
	next := s.copyLocked()
	idx := -1
	for i, current := range next.Profiles {
		if current.ID == p.ID {
			idx = i
			if current.Revision != p.Revision {
				return Summary{}, ErrConflict
			}
			break
		}
	}
	if idx < 0 {
		if p.Revision != 0 {
			return Summary{}, ErrConflict
		}
		if len(next.Profiles) >= MaxProfiles {
			return Summary{}, fmt.Errorf("too many engine profiles")
		}
		p.Revision = 1
		next.Profiles = append(next.Profiles, p)
	} else {
		if p.Kind != next.Profiles[idx].Kind {
			return Summary{}, fmt.Errorf("profile engine kind cannot be changed")
		}
		if p.Revision >= (1<<53)-1 {
			return Summary{}, fmt.Errorf("profile revision limit reached")
		}
		p.Revision++
		next.Profiles[idx] = p
	}
	if err := s.commitLocked(next); err != nil {
		return Summary{}, err
	}
	return p.Summary, nil
}

func (s *Store) Delete(id string, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.copyLocked()
	for i, p := range next.Profiles {
		if p.ID != id {
			continue
		}
		if p.Revision != revision {
			return ErrConflict
		}
		next.Profiles = append(next.Profiles[:i], next.Profiles[i+1:]...)
		// Keep the selected ID unresolved; do not silently choose another route.
		return s.commitLocked(next)
	}
	return ErrNotFound
}

func (s *Store) Selected() *RouteRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Selected == nil {
		return nil
	}
	copy := *s.state.Selected
	return &copy
}

func (s *Store) Select(ref RouteRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref.Kind == "engine" {
		found := false
		for _, p := range s.state.Profiles {
			if p.ID == ref.ProfileID {
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
	}
	next := s.copyLocked()
	next.Selected = &ref
	return s.commitLocked(next)
}

// ClearSelection returns the route to the subscription selection, which is
// also what a catalog that never selected anything means.
func (s *Store) ClearSelection() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Selected == nil {
		return nil
	}
	next := s.copyLocked()
	next.Selected = nil
	return s.commitLocked(next)
}

func (s *Store) copyLocked() catalog {
	next := catalog{Schema: s.state.Schema, Profiles: make([]Profile, len(s.state.Profiles))}
	for i, p := range s.state.Profiles {
		next.Profiles[i] = p.Clone()
	}
	if s.state.Selected != nil {
		r := *s.state.Selected
		next.Selected = &r
	}
	return next
}

func (s *Store) commitLocked(next catalog) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode engine profile catalog")
	}
	defer clear(raw)
	if len(raw) > securestore.MaxPlaintextBytes {
		return fmt.Errorf("engine profile catalog is too large")
	}
	if err := s.disk.Write(raw); err != nil {
		return err
	}
	s.state = next
	return nil
}

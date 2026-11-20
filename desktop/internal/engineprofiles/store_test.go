package engineprofiles

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"whitevpn-desktop/internal/securestore"
)

type memoryDisk struct {
	raw     []byte
	failure error
	reads   int
	writes  int
}

func (d *memoryDisk) Read() ([]byte, error) {
	d.reads++
	if d.raw == nil {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), d.raw...), nil
}
func (d *memoryDisk) Write(raw []byte) error {
	d.writes++
	if d.failure != nil {
		return d.failure
	}
	d.raw = append([]byte(nil), raw...)
	return nil
}

func TestSaveSelectAndDeleteRemainSeparate(t *testing.T) {
	disk := &memoryDisk{}
	s, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	p := fixture(SSH)
	summary, err := s.Save(p)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Revision != 1 || s.Selected() != nil {
		t.Fatal("save selected a profile")
	}
	raw, _ := json.Marshal(s.List())
	if strings.Contains(string(raw), "test-secret") || strings.Contains(string(raw), "config") {
		t.Fatal("profile list contains credentials")
	}
	ref := RouteRef{Kind: "engine", ProfileID: summary.ID}
	if err := s.Select(ref); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(summary.ID, summary.Revision); err != nil {
		t.Fatal(err)
	}
	if s.Selected() == nil || s.Selected().ProfileID != summary.ID || len(s.List()) != 0 {
		t.Fatal("delete changed selected identity")
	}
	reopened, err := Open(disk)
	if err != nil || reopened.Selected().ProfileID != summary.ID {
		t.Fatal("unresolved selection was not retained")
	}
	if _, err := reopened.ForEdit(summary.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted profile remains usable")
	}
}

func TestFailedCommitDoesNotMutateMemoryOrPreviousSnapshot(t *testing.T) {
	disk := &memoryDisk{}
	s, _ := Open(disk)
	first, err := s.Save(fixture(SSH))
	if err != nil {
		t.Fatal(err)
	}
	previous := string(disk.raw)
	p, _ := s.ForEdit(first.ID)
	p.Config.SSH.Password = "changed-secret"
	disk.failure = errors.New("disk full")
	if _, err := s.Save(p); err == nil {
		t.Fatal("failed save succeeded")
	}
	if err := s.Select(RouteRef{Kind: "engine", ProfileID: first.ID}); err == nil {
		t.Fatal("failed select succeeded")
	}
	if err := s.Delete(first.ID, first.Revision); err == nil {
		t.Fatal("failed delete succeeded")
	}
	loaded, _ := s.ForEdit(first.ID)
	if loaded.Config.SSH.Password != "test-secret" || loaded.Revision != 1 || s.Selected() != nil || string(disk.raw) != previous {
		t.Fatal("failed commit changed catalog")
	}
}

func TestOptimisticRevisionAndEditorIsolation(t *testing.T) {
	s, _ := Open(&memoryDisk{})
	first, _ := s.Save(fixture(SSH))
	edit, _ := s.ForEdit(first.ID)
	stale := edit.Clone()
	edit.Name = "updated"
	second, err := s.Save(edit)
	if err != nil || second.Revision != 2 {
		t.Fatal("revision not advanced")
	}
	if _, err := s.Save(stale); !errors.Is(err, ErrConflict) {
		t.Fatal("stale editor overwrote new revision")
	}
	if err := s.Delete(first.ID, first.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale delete accepted")
	}
	edit.Config.SSH.Password = "outside-mutation"
	loaded, _ := s.ForEdit(first.ID)
	if loaded.Config.SSH.Password != "test-secret" {
		t.Fatal("caller can mutate stored config")
	}
}

func TestConcurrentEditorsCannotLoseAnUpdate(t *testing.T) {
	s, _ := Open(&memoryDisk{})
	first, err := s.Save(fixture(SSH))
	if err != nil {
		t.Fatal(err)
	}
	edit, err := s.ForEdit(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Save(edit); results <- err }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 || s.List()[0].Revision != 2 {
		t.Fatal("concurrent editor update was lost")
	}
}

func TestCorruptCatalogNeverDefaultsOrWrites(t *testing.T) {
	for _, raw := range []string{`{`, `{"schema":2,"profiles":[]}`, `{"schema":1,"profiles":[],"unknown":"secret"}`, `{"schema":1,"profiles":[],"selected":{"kind":"unknown"}}`} {
		disk := &memoryDisk{raw: []byte(raw)}
		if _, err := Open(disk); !errors.Is(err, securestore.ErrCorrupt) {
			t.Fatal("invalid catalog did not fail closed")
		}
		if disk.writes != 0 {
			t.Fatal("corrupt catalog overwritten")
		}
	}
	duplicate := fixture(SSH)
	duplicate.Revision = 1
	raw, _ := json.Marshal(catalog{Schema: 1, Profiles: []Profile{duplicate, duplicate}})
	if _, err := Open(&memoryDisk{raw: raw}); !errors.Is(err, securestore.ErrCorrupt) {
		t.Fatal("duplicate profile IDs accepted")
	}
}

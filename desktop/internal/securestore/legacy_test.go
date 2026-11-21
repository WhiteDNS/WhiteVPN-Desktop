package securestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingLegacyProtector struct{ Protector }

func (p failingLegacyProtector) Protect([]byte) ([]byte, error) {
	return nil, errors.New("injected protection failure")
}

func TestLegacyArchiveFailureKeepsSourceAndCorruptArchive(t *testing.T) {
	source := filepath.Join(t.TempDir(), "state.json.123.tmp")
	destination := filepath.Join(t.TempDir(), "recovery.vault")
	content := []byte("interrupted-sensitive-state")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	p := newTestProtector(t)
	if err := ArchiveLegacyFile(source, destination, failingLegacyProtector{p}); err == nil {
		t.Fatal("failed protection accepted")
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(content, after) {
		t.Fatal("source removed before archive verified")
	}
	if err := os.WriteFile(destination, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveLegacyFile(source, destination, p); !errors.Is(err, ErrCorrupt) {
		t.Fatal("corrupt existing archive replaced")
	}
	after, err = os.ReadFile(source)
	if err != nil || !bytes.Equal(content, after) {
		t.Fatal("corrupt archive caused source loss")
	}
	corrupt, _ := os.ReadFile(destination)
	if string(corrupt) != "corrupt" {
		t.Fatal("corrupt archive overwritten")
	}
}

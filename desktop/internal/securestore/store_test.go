package securestore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Portable authenticated protector for snapshot/fault tests; Windows DPAPI has
// additional real platform tests in windows_test.go.
type testProtector struct{ cipher.AEAD }

func newTestProtector(t *testing.T) testProtector {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	return testProtector{a}
}
func (p testProtector) Protect(raw []byte) ([]byte, error) {
	n := make([]byte, p.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return p.Seal(n, n, raw, nil), nil
}
func (p testProtector) Unprotect(raw []byte) ([]byte, error) {
	if len(raw) < p.NonceSize() {
		return nil, ErrCorrupt
	}
	return p.Open(nil, raw[:p.NonceSize()], raw[p.NonceSize():], nil)
}

func TestEncryptedSnapshotRoundTripAndTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "profiles.vault")
	p := newTestProtector(t)
	s := New(path, p)
	secret := []byte(`{"password":"vault-marker-secret"}`)
	if err := s.Write(secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("vault-marker-secret")) {
		t.Fatal("plaintext written to disk")
	}
	got, err := s.Read()
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("snapshot did not round trip")
	}
	wrong := New(path, newTestProtector(t))
	if _, err := wrong.Read(); !errors.Is(err, ErrCorrupt) {
		t.Fatal("wrong protector accepted")
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); !errors.Is(err, ErrCorrupt) {
		t.Fatal("tampered snapshot accepted")
	}
}

func TestCommitFailurePreservesPreviousVaultAndRemovesTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.vault")
	s := New(path, newTestProtector(t))
	if err := s.Write([]byte("previous-secret")); err != nil {
		t.Fatal(err)
	}
	previous, _ := os.ReadFile(path)
	s.replace = func(string, string) error { return errors.New("injected replace failure") }
	if err := s.Write([]byte("new-secret")); err == nil {
		t.Fatal("failed replace succeeded")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(previous, current) {
		t.Fatal("previous vault lost")
	}
	temps, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".vault-*.tmp"))
	if len(temps) != 0 {
		t.Fatal("temporary snapshot leaked")
	}
}

func TestCorruptOrUnavailableVaultDoesNotBecomeEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.vault")
	s := New(path, newTestProtector(t))
	if _, err := s.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing vault not reported")
	}
	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); !errors.Is(err, ErrCorrupt) {
		t.Fatal("corrupt vault accepted")
	}
	if err := New(path, nil).Write([]byte("secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unprotected write accepted")
	}
	if err := s.Write(make([]byte, MaxPlaintextBytes+1)); err == nil {
		t.Fatal("oversized vault accepted")
	}
}

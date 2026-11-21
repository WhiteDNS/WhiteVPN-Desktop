// Package securestore persists an authenticated, user-scoped encrypted snapshot.
// A complete catalog is one payload, so metadata and credentials commit together.
package securestore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const MaxPlaintextBytes = 16 << 20
const maxCiphertextBytes = MaxPlaintextBytes + (64 << 10)

var (
	ErrUnavailable = errors.New("user-scoped credential protection is unavailable on this platform")
	ErrCorrupt     = errors.New("credential vault is corrupt or unavailable for this user")
	magic          = []byte("WhiteVPN-Vault\x00\x01")
)

type Protector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

type Store struct {
	mu        sync.Mutex
	path      string
	protector Protector
	// Replaced only in package tests to inject failure at the commit boundary.
	replace func(string, string) error
}

func New(path string, protector Protector) *Store {
	return &Store{path: filepath.Clean(path), protector: protector, replace: atomicReplace}
}

func (s *Store) Read() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.protector == nil {
		return nil, ErrUnavailable
	}
	if err := rejectLink(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(maxCiphertextBytes+len(magic)+1)))
	if err != nil {
		return nil, fmt.Errorf("read credential vault: %w", err)
	}
	if len(raw) > maxCiphertextBytes+len(magic) || !bytes.HasPrefix(raw, magic) || len(raw) == len(magic) {
		return nil, ErrCorrupt
	}
	plain, err := s.protector.Unprotect(raw[len(magic):])
	if err != nil {
		return nil, ErrCorrupt
	}
	if len(plain) > MaxPlaintextBytes {
		clear(plain)
		return nil, ErrCorrupt
	}
	return plain, nil
}

func (s *Store) Write(plain []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.protector == nil {
		return ErrUnavailable
	}
	if len(plain) > MaxPlaintextBytes {
		return fmt.Errorf("credential vault is too large")
	}
	// Only ciphertext ever reaches the filesystem, including temporary files.
	cipher, err := s.protector.Protect(plain)
	if err != nil {
		return fmt.Errorf("protect credential vault")
	}
	if len(cipher) == 0 || len(cipher) > maxCiphertextBytes {
		return fmt.Errorf("invalid protected credential vault")
	}
	verified, err := s.protector.Unprotect(cipher)
	if err != nil {
		return fmt.Errorf("verify protected credential vault")
	}
	valid := bytes.Equal(plain, verified)
	clear(verified)
	if !valid {
		return fmt.Errorf("verify protected credential vault")
	}
	dir := filepath.Dir(s.path)
	if err := privateDirectory(dir); err != nil {
		return fmt.Errorf("protect credential directory: %w", err)
	}
	if err := rejectLink(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create credential snapshot: %w", err)
	}
	temp := f.Name()
	defer os.Remove(temp)
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(magic); err != nil {
		return err
	}
	if _, err := f.Write(cipher); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	if err := s.replace(temp, s.path); err != nil {
		return fmt.Errorf("commit credential vault: %w", err)
	}
	return nil
}

func rejectLink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential storage must not be a symbolic link")
	}
	return rejectReparse(path)
}

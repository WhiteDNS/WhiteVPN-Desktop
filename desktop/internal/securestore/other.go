//go:build !windows

package securestore

import "os"

// Explicitly unavailable, rather than persisting credentials as plaintext.
func NewUserProtector(purpose string) (Protector, error) { return nil, ErrUnavailable }

func privateDirectory(path string) error {
	if err := rejectLink(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func rejectReparse(path string) error     { return nil }
func atomicReplace(from, to string) error { return os.Rename(from, to) }

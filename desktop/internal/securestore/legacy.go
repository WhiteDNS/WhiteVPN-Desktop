package securestore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// LegacyTemporaryBase recognizes the old <base>.<decimal timestamp>.tmp
// writer's names. Callers still have to verify that base belongs to their store.
func LegacyTemporaryBase(name string) (string, bool) {
	if !strings.HasSuffix(name, ".tmp") {
		return "", false
	}
	stem := strings.TrimSuffix(name, ".tmp")
	index := strings.LastIndexByte(stem, '.')
	if index <= 0 {
		return "", false
	}
	stamp := stem[index+1:]
	if stamp == "" || strings.Trim(stamp, "0123456789") != "" {
		return "", false
	}
	return stem[:index], true
}

// ArchiveLegacyFile preserves an owned legacy temporary file as opaque encrypted
// recovery data. It is never automatically adopted as current state/cache.
func ArchiveLegacyFile(source, destination string, protector Protector) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxPlaintextBytes {
		return fmt.Errorf("legacy recovery requires a bounded regular file")
	}
	if err := rejectLink(source); err != nil {
		return err
	}
	vault := New(destination, protector)
	stored, err := vault.Read()
	clear(stored)
	if errors.Is(err, os.ErrNotExist) {
		file, openErr := os.Open(source)
		if openErr != nil {
			return openErr
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, MaxPlaintextBytes+1))
		closeErr := file.Close()
		defer clear(raw)
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(raw) > MaxPlaintextBytes {
			return fmt.Errorf("legacy recovery file is too large")
		}
		err = vault.Write(raw)
	}
	if err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return fmt.Errorf("encrypted recovery committed but plaintext cleanup failed")
	}
	return nil
}

//go:build windows

package profiles

import "whitevpn-desktop/internal/securestore"

// NewPlatformStore is the production persistence path. Windows never falls
// back to plaintext when its user-scoped protection is unavailable.
func NewPlatformStore(legacyPath string) (*Store, error) {
	protector, err := securestore.NewUserProtector("desktop-state-v1")
	if err != nil {
		return nil, err
	}
	return newProtectedStore(legacyPath, protector), nil
}

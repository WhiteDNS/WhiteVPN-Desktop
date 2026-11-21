//go:build !windows

package profiles

// Legacy persistence on other platforms is outside the Windows vault rollout.
func NewPlatformStore(legacyPath string) (*Store, error) { return NewStore(legacyPath), nil }

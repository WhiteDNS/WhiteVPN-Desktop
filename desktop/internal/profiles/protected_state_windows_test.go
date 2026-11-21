//go:build windows

package profiles

import (
	"path/filepath"
	"testing"
)

func TestWindowsPlatformStoreMigratesUsingRealDPAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := NewStore(path).Save(credentialFixture()); err != nil {
		t.Fatal(err)
	}
	s, err := NewPlatformStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsProtected() {
		t.Fatal("Windows production store is plaintext")
	}
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	assertPrivateFiles(t, s)
	reopened, err := NewPlatformStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.V2RayProfiles[0].UUID != "UUID-credential-marker" || loaded.V2RaySubscriptions[0].URL != credentialFixture().V2RaySubscriptions[0].URL {
		t.Fatal("real DPAPI persistence lost credentials")
	}
}

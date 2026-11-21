//go:build windows

package securestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDPAPIUserScopeAndPurposeBinding(t *testing.T) {
	p, err := NewUserProtector("engine-profiles/v1")
	if err != nil {
		t.Fatal(err)
	}
	s := New(filepath.Join(t.TempDir(), "profiles.vault"), p)
	secret := []byte("real-DPAPI-disposable-fixture")
	if err := s.Write(secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read()
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("DPAPI round trip failed")
	}
	other, err := NewUserProtector("different-purpose")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.path, other).Read(); !errors.Is(err, ErrCorrupt) {
		t.Fatal("purpose binding not enforced")
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("DPAPI vault contains plaintext")
	}
}

func TestPrivateDirectoryACLDoesNotAdmitOtherUsers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	if err := privateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// SIDs compared, not SDDL text: the SDDL of the machine's built-in
	// Administrator (CI runners run as it) is the alias "LA", not its SID.
	broader := []windows.WELL_KNOWN_SID_TYPE{windows.WinWorldSid, windows.WinAuthenticatedUserSid, windows.WinBuiltinUsersSid, windows.WinBuiltinAdministratorsSid}
	found := false
	for i := uint32(0); ; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil {
			break
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(user.User.Sid) {
			found = true
		}
		for _, kind := range broader {
			if sid.IsWellKnown(kind) {
				t.Fatalf("vault DACL admits a broader principal: %s", sid)
			}
		}
	}
	if !found {
		t.Fatal("exact user absent from DACL")
	}
}

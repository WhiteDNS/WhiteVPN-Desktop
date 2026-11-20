//go:build windows

package securestore

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type userProtector struct{ purpose []byte }

func NewUserProtector(purpose string) (Protector, error) {
	if purpose == "" {
		return nil, fmt.Errorf("credential protection purpose is required")
	}
	return userProtector{purpose: []byte("WhiteVPN Desktop\x00" + purpose)}, nil
}

func blob(raw []byte) windows.DataBlob {
	b := windows.DataBlob{Size: uint32(len(raw))}
	if len(raw) > 0 {
		b.Data = &raw[0]
	}
	return b
}

func (p userProtector) Protect(raw []byte) ([]byte, error)   { return p.convert(raw, true) }
func (p userProtector) Unprotect(raw []byte) ([]byte, error) { return p.convert(raw, false) }

func (p userProtector) convert(raw []byte, encrypt bool) ([]byte, error) {
	input, entropy, output := blob(raw), blob(p.purpose), windows.DataBlob{}
	var err error
	if encrypt {
		// No CRYPTPROTECT_LOCAL_MACHINE: elevated helpers do not decrypt user vaults.
		err = windows.CryptProtectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	runtime.KeepAlive(raw)
	runtime.KeepAlive(p.purpose)
	if err != nil {
		return nil, err
	}
	if output.Data == nil {
		return nil, fmt.Errorf("DPAPI returned no data")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	if output.Size > maxCiphertextBytes {
		return nil, fmt.Errorf("DPAPI output is too large")
	}
	data := unsafe.Slice(output.Data, int(output.Size))
	copy := append([]byte(nil), data...)
	if !encrypt {
		clear(data)
	}
	return copy, nil
}

func privateDirectory(path string) error {
	if err := rejectLink(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := rejectLink(path); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func rejectReparse(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("credential storage must not be a reparse point")
	}
	return nil
}

func atomicReplace(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

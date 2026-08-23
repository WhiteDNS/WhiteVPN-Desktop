package helper

import (
	"io/fs"
	"strings"
	"testing"
)

func TestValidateExecAcceptsARootOwnedHelper(t *testing.T) {
	err := ValidateExec("/usr/libexec/whitevpn-desktop/whitevpn-helper", ExecFile{
		Mode: 0o755,
		UID:  0,
	})
	if err != nil {
		t.Fatalf("a correctly installed helper must pass: %v", err)
	}
}

func TestValidateExecRefusesSymlinks(t *testing.T) {
	err := ValidateExec("helper", ExecFile{Mode: 0o755 | fs.ModeSymlink, UID: 0})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlink must be refused outright, got %v", err)
	}
}

func TestValidateExecRefusesNonRootOwnership(t *testing.T) {
	err := ValidateExec("helper", ExecFile{Mode: 0o755, UID: 1000})
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("a user-owned helper is an escalation, got %v", err)
	}
}

func TestValidateExecRefusesGroupAndWorldWritable(t *testing.T) {
	err := ValidateExec("helper", ExecFile{Mode: 0o775, UID: 0})
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable helpers can be rewritten by another account, got %v", err)
	}
	err = ValidateExec("helper", ExecFile{Mode: 0o757, UID: 0})
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable helpers can be rewritten by anyone, got %v", err)
	}
}

func TestValidateExecRefusesNonExecutableAndSpecialFiles(t *testing.T) {
	if err := ValidateExec("helper", ExecFile{Mode: 0o644, UID: 0}); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("a missing exec bit is a packaging bug worth naming, got %v", err)
	}
	err := ValidateExec("device", ExecFile{Mode: 0o644 | fs.ModeDevice, UID: 0})
	if err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("devices are not programs, got %v", err)
	}
}

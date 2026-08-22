// Package helper answers one question for the rest of the app: is there a
// privileged WhiteVPN component installed on this machine that a tunnel can be
// raised through, and can it be trusted?
//
// "Installed" means different things per platform — on Linux it is a
// root-owned helper and core under /usr/libexec that only a distribution
// package could have put there; on macOS it is an SMAppService-registered
// launch daemon inside the signed app bundle. What both share is the rule that
// nothing in a user-writable location, nothing group- or world-writable, and
// nothing that is not exactly the regular file expected may ever be run as
// root.
package helper

import (
	"fmt"
	"io/fs"
)

// ExecFile is everything the trust check needs to know about one file on disk.
// It exists so the checks themselves carry no syscall baggage and can be tested
// on any development machine.
type ExecFile struct {
	Mode fs.FileMode
	UID  int
}

// Version is the helper's request-schema version. The UI reads it before its
// first start-tunnel and refuses a helper that speaks an older protocol,
// rather than discovering the mismatch as garbled behaviour at connect time.
const Version = 1

// Install describes a privileged helper and core that both passed the trust
// check.
type Install struct {
	HelperPath string
	CorePath   string
}

// IsSymlink reports whether the file is a symlink. A symlink is refused before
// anything else: its target can change between the check and the exec, which
// makes every other property of it worthless.
func (f ExecFile) IsSymlink() bool { return f.Mode&fs.ModeSymlink != 0 }

// ValidateExec refuses anything that must not be executed from a privileged
// path.
//
// The rules, each against a real attack:
//   - symlinks: the target is resolved at exec time, so a checked file that is
//     a link proves nothing about what runs;
//   - non-regular files: devices and sockets are not programs;
//   - not owned by root (uid 0): whoever owns it owns the privileged process
//     it becomes;
//   - group- or world-writable: any local account could rewrite it between
//     check and start;
//   - not executable: a missing bit here is a packaging bug worth naming.
func ValidateExec(name string, f ExecFile) error {
	if f.IsSymlink() {
		return fmt.Errorf("%s is a symlink; privileged components must be plain files", name)
	}
	if !f.Mode.IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	if f.UID != 0 {
		return fmt.Errorf("%s is not owned by root", name)
	}
	if f.Mode&0o022 != 0 {
		return fmt.Errorf("%s is writable by accounts other than root (mode %o)", name, f.Mode.Perm())
	}
	if f.Mode&0o111 == 0 {
		return fmt.Errorf("%s is not executable", name)
	}
	return nil
}

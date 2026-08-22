//go:build linux

package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Where a distribution package installs the privileged pieces. Fixed, because
// the whole trust argument is "these files are root-owned and nothing else
// could have put them there": a path chosen at runtime — an environment
// variable, an extracted core beside the user's config — is a path another
// local account controls, and it is never elevated.
const (
	InstallDir   = "/usr/libexec/whitevpn-desktop"
	HelperPath   = InstallDir + "/whitevpn-helper"
	CorePath     = InstallDir + "/mihomo"
	PolicyName   = "org.whitevpn.desktop.policy"
	PolicyPath   = "/usr/share/polkit-1/actions/" + PolicyName
	PolicyAction = "com.whitevpn.desktop.tunnel"
)

// Install describes a helper and core that both passed the trust check.
// (The type lives in helper.go; this platform is the one with an installer.)

// Detect reports the installed helper, or why there is not one this app may
// use. The reason is worth carrying up to the interface: "install from a
// distribution package" and "your helper needs upgrading" lead to different
// actions, and a bare boolean leads to neither.
func Detect() (*Install, error) {
	if _, err := statForPrivilege(HelperPath); err != nil {
		return nil, fmt.Errorf("%s: %w", HelperPath, err)
	}
	if _, err := statForPrivilege(CorePath); err != nil {
		return nil, fmt.Errorf("%s: %w", CorePath, err)
	}
	return &Install{HelperPath: HelperPath, CorePath: CorePath}, nil
}

func statForPrivilege(path string) (ExecFile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ExecFile{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ExecFile{}, fmt.Errorf("cannot read the owner of %s", path)
	}
	file := ExecFile{Mode: info.Mode(), UID: int(stat.Uid)}
	if err := ValidateExec(filepath.Base(path), file); err != nil {
		return ExecFile{}, err
	}
	return file, nil
}

// ExperimentalEnabled is the rollout gate for Linux TUN: one release behind an
// explicit switch while the live matrix proves itself.
var ExperimentalEnabled = func() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("WHITEVPN_EXPERIMENTAL_TUN"))) {
	case "", "0", "false", "no":
		return false
	default:
		return true
	}
}

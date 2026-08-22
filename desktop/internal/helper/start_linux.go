//go:build linux

package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// What the UI may ask the privileged helper to do, and exactly how much it may
// specify. This file is the whole of the request schema: anything not expressed
// here cannot reach the root process, because the entry point parses nothing
// else.
//
// Deliberately absent: any way to choose a core binary, set environment
// variables, pass shell text, or point the core at an arbitrary config. The
// helper resolves the core from its own fixed root-owned location; the UI's
// opinion about executables stops at its own privilege level.

// StartRequest is everything start-tunnel accepts.
type StartRequest struct {
	// SocketPath is the unix socket the core dials back on. It is created and
	// owned by the invoking user before the helper ever runs; the checks below
	// make sure nobody has swapped the directory or the socket underneath it.
	SocketPath string

	// UIPID and UIStartTime identify the exact process instance asking.
	// The start time is what makes a recycled PID worthless as an impostor.
	UIPID       int
	UIStartTime uint64

	// Device names the TUN interface the core will create, used only to clean
	// up this app's own leftovers before starting. Validated hard, because a
	// name is also a path component in sysfs.
	Device string

	// StartupDeadline bounds how long the helper waits for the first sign of
	// life from the UI side before concluding things are wedged.
	StartupDeadlineSeconds int
}

const (
	DefaultStartupDeadline = 30
	MaxStartupDeadline     = 300
	// How long a core is given to leave after being asked before the helper
	// stops asking. Long enough for mihomo to tear its adapter and routes
	// down cleanly; short enough that a wedged core cannot hold the machine.
	ShutdownGrace = 8 * time.Second
)

// deviceNamePattern is stricter than the kernel needs and exactly as strict as
// this helper does: letters, digits, underscore, hyphen; short enough for
// IFNAMSIZ; nothing that could climb out of /sys/class/net/.
var deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)

// ParseStartTunnelArgs parses the arguments after "start-tunnel".
//
// Hand-rolled rather than flag.Parse because every accepted spelling is part
// of the trust boundary: unknown flags, duplicate values and missing values
// are all refusals, not defaults to be filled in.
func ParseStartTunnelArgs(args []string) (StartRequest, error) {
	req := StartRequest{
		StartupDeadlineSeconds: DefaultStartupDeadline,
	}
	seen := map[string]bool{}
	take := func(i *int, name string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("--%s needs a value", name)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		name := strings.TrimPrefix(args[i], "--")
		if args[i] == name || seen[name] {
			return StartRequest{}, fmt.Errorf("unexpected or repeated argument %q", args[i])
		}
		seen[name] = true
		var err error
		switch name {
		case "socket":
			req.SocketPath, err = take(&i, name)
		case "ui-pid":
			var v string
			if v, err = take(&i, name); err == nil {
				req.UIPID, err = strconv.Atoi(v)
			}
		case "ui-start-time":
			var v string
			if v, err = take(&i, name); err == nil {
				req.UIStartTime, err = strconv.ParseUint(v, 10, 64)
			}
		case "device":
			req.Device, err = take(&i, name)
		case "startup-deadline":
			var v string
			if v, err = take(&i, name); err == nil {
				req.StartupDeadlineSeconds, err = strconv.Atoi(v)
			}
		default:
			return StartRequest{}, fmt.Errorf("%q is not an argument start-tunnel accepts", args[i])
		}
		if err != nil {
			return StartRequest{}, fmt.Errorf("--%s: %v", name, err)
		}
	}
	return req, req.Validate()
}

// Validate refuses everything that is not precisely what the UI is expected to
// send, checked against the filesystem rather than taken on faith.
func (r StartRequest) Validate() error {
	if r.UIPID <= 1 {
		return fmt.Errorf("--ui-pid %d is not a process worth supervising", r.UIPID)
	}
	if r.StartupDeadlineSeconds <= 0 || r.StartupDeadlineSeconds > MaxStartupDeadline {
		return fmt.Errorf("--startup-deadline must be between 1 and %d seconds", MaxStartupDeadline)
	}
	if r.Device != "" && !deviceNamePattern.MatchString(r.Device) {
		return fmt.Errorf("--device %q is not an interface name this helper accepts", r.Device)

	}
	return r.validateSocket()
}

// validateSocket proves the control channel belongs to whoever is asking.
//
// Ownership beats location: the socket must sit in a directory owned by the
// same account as the UI process, with permissions that let no third account
// in, and be a socket owned by that account too. Where that directory is
// (/run/user/UID, a private TMPDIR) matters less than who owns it — root
// bypasses permission bits, so the bits have to be right instead.
func (r StartRequest) validateSocket() error {
	path := filepath.Clean(r.SocketPath)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("--socket %q must be absolute", r.SocketPath)
	}
	dir := filepath.Dir(path)

	uiUID, err := ProcRealUID(r.UIPID)
	if err != nil {
		return fmt.Errorf("the UI process could not be identified: %w", err)
	}
	if uiUID == 0 {
		// Never run the interface as root; a request claiming otherwise is
		// either a mistake or a probe.
		return fmt.Errorf("the asking process runs as root, which the interface must not")
	}

	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("the socket's directory is missing: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return fmt.Errorf("the socket's directory is not a plain directory")
	}
	if int(statUID(dirInfo)) != uiUID {
		// A shared directory is acceptable only where the kernel protects each
		// entry: the sticky bit means nobody but a file's owner (or root) can
		// rename or remove it, which is what stops a swapped-in decoy socket.
		// Anything else open to other accounts is refused outright.
		if dirInfo.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("the socket's directory belongs to uid %d, but the UI is uid %d", statUID(dirInfo), uiUID)
		}
	}
	if dirInfo.Mode().Perm()&0o077 != 0 && dirInfo.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("the socket's directory is open to other accounts (mode %o)", dirInfo.Mode().Perm())
	}

	socketInfo, err := os.Lstat(path)
	if err != nil {
		// Absent is fine at validation time: the UI creates the listener
		// moments later and the supervision loop watches for it.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if socketInfo.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("--socket points at something that is not a socket")
	}
	if int(statUID(socketInfo)) != uiUID {
		return fmt.Errorf("the socket belongs to uid %d, but the UI is uid %d", statUID(socketInfo), uiUID)
	}
	return nil
}

// statUID reads the owning uid out of whatever stat the caller already has.
func statUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	// No stat structure means no answer; returning the impossible uid makes
	// every subsequent ownership comparison fail closed.
	return ^uint32(0)
}

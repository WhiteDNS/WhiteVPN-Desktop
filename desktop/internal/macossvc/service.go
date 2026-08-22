//go:build darwin

// Package macossvc is the app's side of the macOS privileged daemon: what is
// registered, whether it has been approved, and how to ask it to do exactly
// three things.
//
// The trust story, in one place:
//
//   - The launch daemon exists only inside the signed application bundle;
//     SMAppService refuses service metadata that lives anywhere else. What the
//     user approves in System Settings IS this bundle's identity.
//   - The UI never hands the daemon anything but a socket path and two
//     numbers. No subscription content, no core path, no shell string crosses
//     this boundary — the daemon resolves the core from its own bundle and
//     checks its signature before it will run it as root.
//   - The daemon checks who is on the other end of the connection (audit
//     token) before answering; this side checks nothing less of the daemon,
//     because a root process that takes dictation from any caller is not a
//     helper but an escalation.
package macossvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// LaunchdPlistName is the file this app's bundle carries in
// Contents/Library/LaunchDaemons/. SMAppService registers by this name and
// keeps the metadata inside the signed bundle — which is precisely why a
// helper cannot be smuggled in from outside it.
const LaunchdPlistName = "com.whitevpn.vpn.daemon.plist"

// ProtocolVersion is the version of the request/reply schema the UI speaks.
// The daemon answers with its own; a mismatch is reported as "helper needs
// upgrading" rather than discovered as garbled traffic at connect time.
const ProtocolVersion = 1

// Status is where the registration stands with the operating system.
type Status int

const (
	StatusUnknown Status = iota
	// StatusNotRegistered means no daemon for this bundle is known to launchd.
	StatusNotRegistered
	// StatusEnabled means registered and approved; the daemon can run.
	StatusEnabled
	// StatusRequiresApproval means registered and waiting for the user to flip
	// the switch in System Settings > General > Login Items.
	StatusRequiresApproval
	// StatusNotFound means the plist names something launchd cannot locate —
	// typically an upgraded bundle whose daemon moved or was removed.
	StatusNotFound
)

// ErrUnsupportedPlatform is returned on macOS versions without SMAppService
// (< 13) or when the bridge could not load. Callers report tunnel mode as
// needing a newer macOS rather than failing mysteriously later.
var ErrUnsupportedPlatform = errors.New("macossvc: SMAppService needs macOS 13 or newer")

// Service is one registered daemon, addressed by the plist name in this app's
// bundle.
type Service struct{ plistName string }

// Daemon returns the handle for this app's launch daemon.
func Daemon() Service { return Service{plistName: LaunchdPlistName} }

// Registration reports where the daemon stands with launchd.
func (s Service) Registration() (Status, error) {
	raw, err := s.status()
	if err != nil {
		return StatusUnknown, err
	}
	switch raw {
	case 1: // SMAppServiceStatusNotRegistered
		return StatusNotRegistered, nil
	case 2: // SMAppServiceStatusEnabled
		return StatusEnabled, nil
	case 3: // SMAppServiceStatusRequiresApproval
		return StatusRequiresApproval, nil
	case 4: // SMAppServiceStatusNotFound
		return StatusNotFound, nil
	default:
		return StatusUnknown, fmt.Errorf("macossvc: unknown registration status %d", raw)
	}
}

// Register asks the system to enable the daemon, which sends the user to the
// approval flow the first time.
func (s Service) Register() error { return s.register() }

// Unregister disables the daemon again.
func (s Service) Unregister() error { return s.unregister() }

// Request sends one operation to the running daemon and returns its JSON
// reply. Operations are exactly: "status", "start", "stop". Anything richer —
// paths, subscription bodies, arguments — must not cross this boundary and the
// daemon refuses them even if asked.
func (s Service) Request(op string, timeoutMs int) (string, error) {
	switch op {
	case "status", "start", "stop":
	default:
		return "", fmt.Errorf("macossvc: %q is not an operation the daemon offers", op)
	}
	reply, err := s.request(op, timeoutMs)
	if err != nil {
		return "", err
	}
	return reply, nil
}

// Reply is the shape every daemon answer shares.
type Reply struct {
	OK      bool   `json:"ok"`
	Version int    `json:"version"`
	Error   string `json:"error,omitempty"`
	Running bool   `json:"running,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

// ParseReply decodes a daemon answer and turns a structured refusal into an
// error, so callers never compare JSON strings by hand.
func ParseReply(raw string) (Reply, error) {
	var reply Reply
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &reply); err != nil {
		return Reply{}, fmt.Errorf("macossvc: unreadable reply from the daemon: %w", err)
	}
	if !reply.OK && reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	if !reply.OK {
		return reply, errors.New("macossvc: the daemon refused without a reason")
	}
	return reply, nil
}

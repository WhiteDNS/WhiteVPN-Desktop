//go:build linux

package helper

import (
	"os"
	"strconv"
	"testing"
)

func TestParseAcceptsTheCanonicalRequest(t *testing.T) {
	req, err := ParseStartTunnelArgs([]string{
		"--socket", "/run/user/1000/whitevpn-engine-ab12.sock",
		"--ui-pid", "4242",
		"--ui-start-time", "1234567",
		"--device", "WhiteVPN",
		"--startup-deadline", "45",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.SocketPath != "/run/user/1000/whitevpn-engine-ab12.sock" ||
		req.UIPID != 4242 || req.UIStartTime != 1234567 ||
		req.Device != "WhiteVPN" || req.StartupDeadlineSeconds != 45 {
		t.Fatalf("parsed wrong: %+v", req)
	}
}

func TestParseDefaultsDeadlineAndDevice(t *testing.T) {
	// The socket check needs a live process; the test's own will do.
	req, err := ParseStartTunnelArgs([]string{
		"--socket", "/run/user/" + strconv.Itoa(os.Getuid()) + "/x.sock",
		"--ui-pid", strconv.Itoa(os.Getpid()),
		"--ui-start-time", strconv.FormatUint(SelfStartTime(), 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.StartupDeadlineSeconds != DefaultStartupDeadline {
		t.Fatalf("deadline default moved: %d", req.StartupDeadlineSeconds)
	}
	if req.Device != "" {
		t.Fatalf("device should default to empty, got %q", req.Device)
	}
}

func TestParseRefusesEverythingForeign(t *testing.T) {
	cases := map[string][]string{
		"unknown flag":  {"--socket", "/x.sock", "--core", "/tmp/evil"},
		"bare value":    {"/usr/bin/mihomo"},
		"missing value": {"--socket"},
		"duplicate":     {"--socket", "/a.sock", "--socket", "/b.sock", "--ui-pid", "2", "--ui-start-time", "0"},
	}
	for name, args := range cases {
		if _, err := ParseStartTunnelArgs(args); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func TestValidateFailsClosedOnPureChecks(t *testing.T) {
	cases := []struct {
		name string
		req  StartRequest
	}{
		{"relative socket", StartRequest{SocketPath: "sock"}},
		{"zero deadline", StartRequest{UIPID: os.Getpid(), StartupDeadlineSeconds: 0}},
		{"absurd deadline", StartRequest{UIPID: os.Getpid(), StartupDeadlineSeconds: MaxStartupDeadline + 1}},
		{"path in device", StartRequest{Device: "../../etc"}},
		{"slashy device", StartRequest{Device: "eth0/x"}},
		{"overlong device", StartRequest{Device: "sixteenchars00000"}},
	}
	for _, c := range cases {
		if err := c.req.Validate(); err == nil {
			t.Fatalf("%s must fail validation (%+v)", c.name, c.req)
		}
	}
}

// These two need a real /proc. They run wherever the package is tested on
// Linux; elsewhere they are meaningless rather than failing.
func TestValidateRejectsDeadProcessAndRootUI(t *testing.T) {
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no procfs here")
	}
	dead := StartRequest{SocketPath: "/run/user/1000/s.sock", UIPID: 1 << 30, UIStartTime: 1}
	if err := dead.Validate(); err == nil {
		t.Fatal("a process that cannot be identified must fail validation")
	}
	self := StartRequest{SocketPath: "/run/user/" + strconv.Itoa(os.Getuid()) + "/s.sock",
		UIPID: os.Getpid(), UIStartTime: SelfStartTime()}
	// The test itself may be running as root (in which case refusing IS the
	// expected answer) or as a user whose runtime dir differs.
	if os.Getuid() == 0 {
		if err := self.Validate(); err == nil {
			t.Fatal("a root asking-process must be refused")
		}
	}
}

// A device name that survives validation is one that can never become a path:
// no separators, no dots, bounded by IFNAMSIZ.
func TestHonestDeviceNamePasses(t *testing.T) {
	req := StartRequest{UIPID: os.Getpid(), UIStartTime: SelfStartTime(), Device: "utun9"}
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no procfs here")
	}
	if err := req.Validate(); err != nil && !os.IsNotExist(err) {
		// The only permitted failure here is the test environment having no
		// such directory yet — never a name rejection.
		t.Fatalf("an honest device name must pass: %v", err)
	}
}

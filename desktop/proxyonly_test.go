package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

// The three modes, and which of them makes the port somebody else's business.
func TestProxyOnlyIsBothOthersOff(t *testing.T) {
	cases := []struct {
		name     string
		settings model.WhiteVPNSettings
		want     bool
	}{
		{"tunnel", model.WhiteVPNSettings{TunEnabled: true, SetSystemProxy: false}, false},
		{"system proxy", model.WhiteVPNSettings{TunEnabled: false, SetSystemProxy: true}, false},
		{"proxy only", model.WhiteVPNSettings{TunEnabled: false, SetSystemProxy: false}, true},
		// The tunnel wins over the system proxy at connect, so this is not
		// proxy-only either — something is still redirecting the machine.
		{"both", model.WhiteVPNSettings{TunEnabled: true, SetSystemProxy: true}, false},
	}
	for _, tc := range cases {
		if got := proxyOnly(tc.settings); got != tc.want {
			t.Errorf("%s: proxyOnly = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// With the tunnel up or the machine pointed here, nothing the user configured
// depends on the number, so a taken port is worked around rather than reported.
func TestATakenPortIsWorkedAroundWhenNobodyIsRelyingOnIt(t *testing.T) {
	held, port := holdAPort(t)
	defer held.Close()

	settings := model.WhiteVPNSettings{TunEnabled: false, SetSystemProxy: true, ListenPort: port}
	got, err := chooseProxyPort(settings)
	if err != nil {
		t.Fatalf("this mode should not fail over a port: %v", err)
	}
	if got == port {
		t.Fatal("the held port was handed out anyway")
	}
	if got <= 0 {
		t.Fatalf("expected some usable port, got %d", got)
	}
}

// In proxy-only mode the port is what somebody typed into Telegram. Binding a
// different one silently means their program stops working days later, in
// another application, with nothing anywhere connecting that to this app.
func TestATakenPortIsReportedInProxyOnlyMode(t *testing.T) {
	held, port := holdAPort(t)
	defer held.Close()

	settings := model.WhiteVPNSettings{TunEnabled: false, SetSystemProxy: false, ListenPort: port}
	_, err := chooseProxyPort(settings)
	if err == nil {
		t.Fatal("a port that cannot be had must be reported, not worked around")
	}
	// The message has to name the port and say what to do about it.
	for _, want := range []string{fmt.Sprint(port), "Settings"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message should mention %q: %v", want, err)
		}
	}
}

// Sharing on the network makes the port somebody else's business the same way
// proxy-only does — a device that was told to connect to it cannot follow a
// silent switch to a different one.
func TestATakenPortIsReportedWhenSharedOnTheNetwork(t *testing.T) {
	held, port := holdAPort(t)
	defer held.Close()

	for _, settings := range []model.WhiteVPNSettings{
		{TunEnabled: false, SetSystemProxy: true, AllowLAN: true, ListenPort: port},
		{TunEnabled: true, SetSystemProxy: false, AllowLAN: true, ListenPort: port},
	} {
		_, err := chooseProxyPort(settings)
		if err == nil {
			t.Fatal("a port that cannot be had must be reported when it is shared, not worked around")
		}
		if !strings.Contains(err.Error(), fmt.Sprint(port)) {
			t.Errorf("the message should mention %d: %v", port, err)
		}
		// The system proxy is not what is on trial here; sharing is.
		if strings.Contains(err.Error(), "system proxy") {
			t.Errorf("blaming the system proxy for a sharing conflict is misleading: %v", err)
		}
	}
}

// Without sharing, the two settings behave exactly as they did before this: a
// taken port is worked around, not reported.
func TestATakenPortIsStillWorkedAroundWithoutSharing(t *testing.T) {
	held, port := holdAPort(t)
	defer held.Close()

	settings := model.WhiteVPNSettings{TunEnabled: false, SetSystemProxy: true, AllowLAN: false, ListenPort: port}
	got, err := chooseProxyPort(settings)
	if err != nil {
		t.Fatalf("this mode should not fail over a port: %v", err)
	}
	if got == port {
		t.Fatal("the held port was handed out anyway")
	}
}

// A free port is used as asked, in every mode.
func TestAFreePortIsUsedAsAsked(t *testing.T) {
	held, port := holdAPort(t)
	held.Close() // now free, and unlikely to be retaken in this instant

	for _, settings := range []model.WhiteVPNSettings{
		{TunEnabled: false, SetSystemProxy: false, ListenPort: port},
		{TunEnabled: false, SetSystemProxy: true, ListenPort: port},
	} {
		got, err := chooseProxyPort(settings)
		if err != nil {
			t.Fatal(err)
		}
		if got != port {
			t.Errorf("asked for %d, got %d", port, got)
		}
	}
}

// An unset port falls back to the engine's usual one rather than to zero, which
// the kernel would read as "any port" — a different one every run, and no
// number a user could configure anything with.
func TestAnUnsetPortIsNotTreatedAsAny(t *testing.T) {
	got, err := chooseProxyPort(model.WhiteVPNSettings{TunEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatal("zero would let the kernel choose")
	}
}

func holdAPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener, listener.Addr().(*net.TCPAddr).Port
}

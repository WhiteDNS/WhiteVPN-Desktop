//go:build darwin

package sysproxy

// Asking a real Mac the questions this package's rules are built on.
//
// Two of them cannot be answered by reading Apple's documentation, because it
// does not say. Both are load-bearing:
//
//   - Does `networksetup` keep the server address after the proxy is switched
//     off? Satisfies exists because the answer was assumed to be yes. If it is
//     no, the rule is still correct — it does not read the address when the
//     target is off — but the comment explaining it is wrong, and the next
//     person to touch it would be reasoning from a false premise.
//   - Is the bypass list readable? Verify was changed to stop comparing it after
//     that was traced through the source. A machine can say so directly.
//
// It is written because there is no Mac to try these on by hand, and CI already
// runs this package's tests on macos-latest. A hosted runner is a real Mac that
// can be asked.
//
// It changes the machine's own network settings, so it does not run unless it is
// asked for by name. Nobody's laptop should have its proxy reconfigured by
// `go test ./...`, and an ephemeral runner is the only place where being wrong
// about the restore costs nothing.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const integrationEnv = "WHITEVPN_SYSPROXY_INTEGRATION"

func TestOnARealMacTheAddressSurvivesTurningTheProxyOff(t *testing.T) {
	service := integrationService(t)

	// Everything below is undone in reverse, whatever the test does.
	restoreServiceProxy(t, service)

	sudoNetworksetup(t, "-setsecurewebproxy", service, "127.0.0.1", "2080")
	if state := readService(t, service); !state.Enabled || state.Server != "127.0.0.1:2080" {
		t.Fatalf("setting the proxy did not take: %#v", state)
	}

	sudoNetworksetup(t, "-setsecurewebproxystate", service, "off")
	off := readService(t, service)

	// The question itself. Recorded either way, because the answer is what the
	// comment on Satisfies claims and a future reader deserves the real one.
	if off.Server == "" {
		t.Logf("this Mac CLEARS the address when the proxy is switched off: %#v", off)
	} else {
		t.Logf("this Mac KEEPS the address when the proxy is switched off: %#v", off)
	}

	// The rule that matters, which has to hold whichever way that went.
	if !off.Satisfies(State{Enabled: false}) {
		t.Fatalf("a machine with the proxy switched off does not satisfy being asked to switch it off: %#v", off)
	}
	if off.Enabled {
		t.Fatalf("networksetup reported the proxy still enabled after being told to switch it off: %#v", off)
	}
}

// The other half: a proxy that was asked for and is really there has to verify.
//
// This is the path that has always worked in the field — users' proxies were
// being set — so a failure here means the rule drifted away from the machine
// rather than the machine surprising us.
func TestOnARealMacAConfiguredProxyVerifies(t *testing.T) {
	service := integrationService(t)
	restoreServiceProxy(t, service)

	want := State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}
	sudoNetworksetup(t, "-setsecurewebproxy", service, "127.0.0.1", "2080")
	args := append([]string{"-setproxybypassdomains", service}, bypassDomains(DefaultBypass)...)
	sudoNetworksetup(t, args...)

	got := readService(t, service)
	if !got.Satisfies(want) {
		t.Fatalf("a correctly configured proxy failed verification: got %#v, want %#v", got, want)
	}
	// The reason Satisfies is not SameAs. If a read ever does return the bypass
	// list, this is where that gets noticed rather than in a user's log.
	if got.Override != "" {
		t.Logf("this Mac DOES report a bypass list (%q) — Satisfies could compare it after all", got.Override)
	}
	if err := verifyServices([]string{service}, want, serviceProxy); err != nil {
		t.Fatalf("verifyServices rejected a machine that is configured correctly: %v", err)
	}
}

// integrationService picks a network service to work on, and skips the test
// unless it was explicitly asked for.
func integrationService(t *testing.T) string {
	t.Helper()
	if os.Getenv(integrationEnv) == "" {
		t.Skipf("set %s=1 to run this: it reconfigures the machine's own proxy settings", integrationEnv)
	}
	services, err := networkServices()
	if err != nil {
		t.Fatalf("could not list this machine's network services: %v", err)
	}
	if len(services) == 0 {
		t.Skip("this machine has no enabled network services to configure")
	}
	return services[0]
}

// restoreServiceProxy records one service's proxy settings and puts them back
// when the test ends, whether it passed, failed, or panicked.
func restoreServiceProxy(t *testing.T, service string) {
	t.Helper()
	before := readService(t, service)
	t.Cleanup(func() {
		if before.Enabled {
			host, port := splitEndpoint(before.Server)
			sudoNetworksetup(t, "-setsecurewebproxy", service, host, port)
			return
		}
		sudoNetworksetup(t, "-setsecurewebproxystate", service, "off")
	})
}

func readService(t *testing.T, service string) State {
	t.Helper()
	state, err := serviceProxy(service)
	if err != nil {
		t.Fatalf("could not read %s: %v", service, err)
	}
	return state
}

// sudoNetworksetup drives networksetup as root.
//
// Not through Apply, which asks for the password through osascript and would
// hang with nobody there to answer. A hosted runner has passwordless sudo, which
// is the whole reason this can be asked of CI at all.
func sudoNetworksetup(t *testing.T, args ...string) {
	t.Helper()
	command := exec.Command("/usr/bin/sudo", append([]string{"-n", networksetup}, args...)...)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sudo networksetup %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

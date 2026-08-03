package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTunRouteGuardPlansLinuxBypassAndSplitRoutes(t *testing.T) {
	guard := &xrayTunRouteGuard{
		platform:      "linux",
		interfaceName: "xray0",
		ipv6:          true,
		serverIPs:     []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")},
		gateway4:      "192.0.2.1",
		dev4:          "eth0",
		gateway6:      "2001:db8:1::1",
		dev6:          "eth0",
	}

	commands := commandStrings(guard.linuxAddRoutes())
	for _, want := range []string{
		"ip route add 203.0.113.10/32 via 192.0.2.1 dev eth0",
		"ip -6 route add 2001:db8::10/128 via 2001:db8:1::1 dev eth0",
		"ip route add 0.0.0.0/1 dev xray0",
		"ip route add 128.0.0.0/1 dev xray0",
		"ip -6 route add ::/1 dev xray0",
		"ip -6 route add 8000::/1 dev xray0",
	} {
		if !hasCommand(commands, want) {
			t.Fatalf("expected command %q in %#v", want, commands)
		}
	}
}

func TestTunRouteGuardPlansDarwinBypassAndSplitRoutes(t *testing.T) {
	guard := &xrayTunRouteGuard{
		platform:      "darwin",
		interfaceName: "utun20",
		ipv6:          true,
		serverIPs:     []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")},
		gateway4:      "192.0.2.1",
		gateway6:      "2001:db8:1::1",
	}

	commands := commandStrings(guard.darwinAddRoutes())
	for _, want := range []string{
		"route -n add -host 203.0.113.10 192.0.2.1",
		"route -n add -inet6 -host 2001:db8::10 2001:db8:1::1",
		"route -n add -net 0.0.0.0/1 -iface utun20",
		"route -n add -net 128.0.0.0/1 -iface utun20",
		"route -n add -inet6 -net ::/1 -iface utun20",
		"route -n add -inet6 -net 8000::/1 -iface utun20",
	} {
		if !hasCommand(commands, want) {
			t.Fatalf("expected command %q in %#v", want, commands)
		}
	}
}

func TestTunRouteGuardPlansWindowsBypassAndSplitRoutes(t *testing.T) {
	guard := &xrayTunRouteGuard{
		platform:      "windows",
		interfaceName: "WhiteDNS Tunnel",
		ipv6:          true,
		serverIPs:     []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")},
		gateway4:      "192.0.2.1",
		gateway6:      "2001:db8:1::1",
	}

	commands := commandStrings(guard.windowsAddRoutes("24"))
	for _, want := range []string{
		"route add 203.0.113.10 mask 255.255.255.255 192.0.2.1 metric 1",
		"netsh interface ipv6 add route 2001:db8::10/128 WhiteDNS Tunnel 2001:db8:1::1 publish=no",
		"route add 0.0.0.0 mask 128.0.0.0 0.0.0.0 if 24 metric 1",
		"route add 128.0.0.0 mask 128.0.0.0 0.0.0.0 if 24 metric 1",
		"netsh interface ipv6 add route ::/1 WhiteDNS Tunnel :: publish=no",
		"netsh interface ipv6 add route 8000::/1 WhiteDNS Tunnel :: publish=no",
	} {
		if !hasCommand(commands, want) {
			t.Fatalf("expected command %q in %#v", want, commands)
		}
	}
}

func TestTunRouteGuardPlansWindowsExactDeleteRoutes(t *testing.T) {
	guard := &xrayTunRouteGuard{
		platform:      "windows",
		interfaceName: "WhiteDNS Tunnel",
		ipv6:          true,
		serverIPs:     []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")},
		gateway4:      "192.0.2.1",
	}

	commands := commandStrings(guard.windowsDeleteRoutes())
	for _, want := range []string{
		"route delete 203.0.113.10 mask 255.255.255.255 192.0.2.1",
		"route delete 0.0.0.0 mask 128.0.0.0 0.0.0.0",
		"route delete 128.0.0.0 mask 128.0.0.0 0.0.0.0",
		"netsh interface ipv6 delete route 2001:db8::10/128 WhiteDNS Tunnel",
		"netsh interface ipv6 delete route ::/1 WhiteDNS Tunnel",
		"netsh interface ipv6 delete route 8000::/1 WhiteDNS Tunnel",
	} {
		if !hasCommand(commands, want) {
			t.Fatalf("expected command %q in %#v", want, commands)
		}
	}
	for _, command := range commands {
		if command == "route delete 0.0.0.0" || command == "route delete 128.0.0.0" {
			t.Fatalf("unsafe broad Windows route delete in %#v", commands)
		}
	}
}

func TestRestoreTunRouteSnapshotFileRestoresDeleteRoutes(t *testing.T) {
	runner := &fakeTunRunner{}
	snapshot := tunRouteSnapshot{
		Platform:      "linux",
		InterfaceName: "xray0",
		DeleteRoutes: []tunRouteCommand{
			{Name: "ip", Args: []string{"route", "del", "0.0.0.0/1"}},
			{Name: "ip", Args: []string{"route", "del", "128.0.0.0/1"}},
		},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), ".wd-test.tun-routes.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := restoreTunRouteSnapshotFile(context.Background(), path, "linux", runner.run); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.calls)
	want := []string{
		"ip route del 128.0.0.0/1",
		"ip route del 0.0.0.0/1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected restore order:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestCleanupStaleLaunchFilesRestoresTunSnapshot(t *testing.T) {
	runner := &fakeTunRunner{}
	runtimeDir := t.TempDir()
	snapshot := tunRouteSnapshot{
		Platform:      "linux",
		InterfaceName: "xray0",
		DeleteRoutes: []tunRouteCommand{
			{Name: "ip", Args: []string{"route", "del", "0.0.0.0/1"}},
		},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runtimeDir, ".wd-test.tun-routes.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cleanupStaleLaunchFiles(runtimeDir, time.Second, nil, "linux", runner.run); err != nil {
		t.Fatal(err)
	}
	if got := commandStrings(runner.calls); strings.Join(got, "\n") != "ip route del 0.0.0.0/1" {
		t.Fatalf("expected stale TUN route cleanup, got %#v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected stale TUN snapshot to be removed, err=%v", err)
	}
}

func TestWindowsRouteRestoreNormalizesUnsafeLegacySplitDeletes(t *testing.T) {
	runner := &fakeTunRunner{}
	guard := &xrayTunRouteGuard{
		platform: "windows",
		runner:   runner.run,
		deleteRoutes: []tunRouteCommand{
			{Name: "route", Args: []string{"delete", "0.0.0.0"}},
			{Name: "route", Args: []string{"delete", "128.0.0.0"}},
		},
		restoreForced: true,
	}

	if err := guard.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.calls)
	want := []string{
		"route delete 128.0.0.0 mask 128.0.0.0 0.0.0.0",
		"route delete 0.0.0.0 mask 128.0.0.0 0.0.0.0",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected normalized restore commands:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestTunRouteGuardRestoreSkipsBeforeApply(t *testing.T) {
	runner := &fakeTunRunner{}
	guard := &xrayTunRouteGuard{
		platform: "linux",
		runner:   runner.run,
		deleteRoutes: []tunRouteCommand{
			{Name: "ip", Args: []string{"route", "del", "0.0.0.0/1"}},
		},
	}

	if err := guard.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("restore before apply should not mutate routes, got %#v", commandStrings(runner.calls))
	}
}

func TestPrepareTunRouteGuardDoesNotMutateRoutesOnPreflightFailure(t *testing.T) {
	runner := &fakeTunRunner{
		errors: map[string]error{
			"ip route show default": errors.New("no default route"),
		},
	}
	manager := NewManager(Options{
		SystemProxyPlatform: "linux",
		SystemProxyRunner:   runner.run,
	}, Callbacks{})

	_, err := manager.prepareTunRouteGuard(context.Background(), XrayLaunchConfig{
		TunEnabled:       true,
		TunInterfaceName: "xray0",
		TunServerHost:    "203.0.113.10",
		TunIPv6:          false,
	}, filepath.Join(t.TempDir(), "xray"))
	if err == nil {
		t.Fatal("expected preflight failure")
	}
	for _, call := range commandStrings(runner.calls) {
		if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.HasPrefix(call, "pkexec ") {
			t.Fatalf("preflight failure should not mutate routes, got calls %#v", commandStrings(runner.calls))
		}
	}
}

func TestParseWindowsRouteInterfaceIndex(t *testing.T) {
	output := `
Interface List
 12...00 ff 11 22 33 44 ......Intel(R) Ethernet
 24...00 ff 55 66 77 88 ......WhiteDNS Tunnel
===========================================================================
`
	if got := parseWindowsRouteInterfaceIndex(output, "WhiteDNS Tunnel"); got != "24" {
		t.Fatalf("expected WhiteDNS Tunnel index 24, got %q", got)
	}
}

func TestWindowsInterfaceIndexFallsBackToNetshName(t *testing.T) {
	runner := &fakeTunRunner{
		outputs: map[string]string{
			"route print": `
Interface List
 24...00 ff 55 66 77 88 ......Wintun Userspace Tunnel
===========================================================================
`,
			"netsh interface ipv4 show interfaces": `
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
 24          25        1500  connected     WhiteDNS Tunnel
`,
		},
	}
	guard := &xrayTunRouteGuard{
		platform:      "windows",
		runner:        runner.run,
		interfaceName: "WhiteDNS Tunnel",
	}

	got, err := guard.windowsInterfaceIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "24" {
		t.Fatalf("expected netsh fallback index 24, got %q", got)
	}
}

type fakeTunRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   []tunRouteCommand
}

func (r *fakeTunRunner) run(_ context.Context, name string, args ...string) (string, error) {
	call := tunRouteCommand{Name: name, Args: append([]string(nil), args...)}
	r.calls = append(r.calls, call)
	key := commandString(call)
	if r.errors != nil {
		if err, ok := r.errors[key]; ok {
			return "", err
		}
	}
	if r.outputs != nil {
		return r.outputs[key], nil
	}
	return "", nil
}

func commandStrings(commands []tunRouteCommand) []string {
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, commandString(command))
	}
	return out
}

func commandString(command tunRouteCommand) string {
	return strings.TrimSpace(command.Name + " " + strings.Join(command.Args, " "))
}

func hasCommand(commands []string, want string) bool {
	for _, command := range commands {
		if command == want {
			return true
		}
	}
	return false
}

//go:build linux

package engine

// Asking a real Linux machine whether the tunnel actually comes up.
//
// The Linux elevation path (elevate_linux.go) and the route-verification logic
// that reads it back (internal/session's tun_linux.go) were both written
// without a Linux machine to try them on, the same position the macOS proxy
// work was in before a CI runner answered it directly. A hosted Linux runner is
// a real Linux machine with passwordless sudo, so the same move applies here:
// ask it, rather than trust the code.
//
// Two things this settles that reading the source cannot:
//
//   - That CAP_NET_ADMIN by way of a root process actually lets mihomo create
//     the adapter and install routes, on a machine that has never been
//     configured for this by hand.
//   - That mihomo's Linux route installation — which the comment on
//     TunOptions.StrictRoute says goes through "unreachable policy rules"
//     rather than routes attached directly to the device the way Windows does
//     — still resolves correctly when asked with `ip route get`, the same tool
//     tun_linux.go's verifyTunnel uses in production.
//
// It runs as root rather than through pkexec, because pkexec needs a polkit
// authentication agent and an interactive session that a hosted runner has
// neither of — but elevate_linux.go already has a direct path for exactly this
// case: a caller that is root does not need to ask again. Running the whole
// test process under sudo takes that path, which is the same code a real
// desktop session reaches once its own password prompt is answered, not a
// separate one written only for CI.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

const tunIntegrationEnv = "WHITEVPN_TUN_INTEGRATION"

func TestOnARealLinuxMachineTheTunnelActuallyComesUp(t *testing.T) {
	if os.Getenv(tunIntegrationEnv) == "" {
		t.Skipf("set %s=1 to run this: it creates a real network adapter and needs root", tunIntegrationEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("this has to run as root — elevate_linux.go's direct-launch path is what is being asked about")
	}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2's ip is not installed, so the routing decision cannot be read")
	}

	// The address does not have to answer. Bringing the adapter up and
	// installing its routes is mihomo's own startup work and happens
	// regardless of whether the one proxy in the group can be reached — the
	// same way ValidateConfig's tests use addresses nobody will ever dial.
	convertedProxies, err := mihomoconf.ConvertLinks(
		"vless://11111111-2222-3333-4444-555555555555@198.51.100.1:443?security=tls&type=tcp#Unreachable")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	proxies, err := mihomoconf.BuildProxiesYAML(convertedProxies, mihomoconf.SplitTunnel{})
	if err != nil {
		t.Fatalf("build proxies: %v", err)
	}

	tun := mihomoconf.DefaultTunOptions()
	// A name of its own, distinct from what a real connect would use, so a
	// leftover from a previous run — or a real WhiteVPN connection on the same
	// machine, however unlikely on a CI runner — is never mistaken for this
	// test's adapter.
	tun.Device = "whitevpn-tun-test"
	config := mihomoconf.Render(proxies, mihomoconf.Options{
		Secret:     "tun-integration-test",
		ProxyGroup: mihomoconf.SelectGroup,
		Tun:        tun,
	})

	home := t.TempDir()
	configPath := home + "/config.yaml"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	proc, err := Spawn(ctx, SpawnOptions{
		CorePath:       corePath(t),
		WorkingDir:     home,
		ConnectTimeout: 20 * time.Second,
		// The path this is actually testing. Root already, so this does not
		// raise a pkexec prompt — it takes elevate_linux.go's other branch,
		// the one a real desktop session reaches once its own prompt is
		// answered.
		Elevated: true,
	})
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer func() { _ = proc.Stop(context.Background()) }()

	if err := proc.Init(ctx, home, 36); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := proc.ValidateConfig(ctx, configPath); err != nil {
		t.Fatalf("the engine could not read the config: %v\n---\n%s", err, config)
	}
	if err := proc.SetupConfig(ctx, map[string]string{}, "http://198.51.100.1/"); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if err := proc.StartListener(ctx); err != nil {
		t.Fatalf("start listener: %v", err)
	}

	// The adapter does not necessarily exist the instant StartListener returns
	// — this is the same race waitForTunnel exists to cover in production —
	// so it is polled rather than checked once.
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = verifyRealRouteThroughDevice(ipPath, tun.Device); lastErr == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the tunnel never came up: %v", lastErr)
}

// verifyRealRouteThroughDevice is a deliberately independent check from
// tun_linux.go's verifyRouteThrough: internal/engine cannot import
// internal/session, which already imports internal/engine, so this proves the
// same fact — that a real packet would leave through the tunnel — without
// sharing code with what it is verifying.
func verifyRealRouteThroughDevice(ipPath, device string) error {
	if _, err := net.InterfaceByName(device); err != nil {
		return fmt.Errorf("adapter %q does not exist yet: %w", device, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ipPath, "route", "get", "1.1.1.1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route get: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), "dev "+device+" ") && !strings.HasSuffix(strings.TrimSpace(string(out)), "dev "+device) {
		return fmt.Errorf("traffic does not resolve through %q: %s", device, strings.TrimSpace(string(out)))
	}
	return nil
}

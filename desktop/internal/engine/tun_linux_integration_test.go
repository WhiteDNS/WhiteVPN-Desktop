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
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

const tunIntegrationEnv = "WHITEVPN_TUN_INTEGRATION"

func TestOnARealLinuxMachineTheTunnelActuallyComesUp(t *testing.T) {
	// The only skip. Everything past this point was explicitly asked for, so a
	// missing precondition is a broken harness rather than a machine that
	// cannot answer — and a skip there would read as a pass, which is how the
	// first version of this went green while proving nothing.
	if os.Getenv(tunIntegrationEnv) == "" {
		t.Skipf("set %s=1 to run this: it creates a real network adapter and needs root", tunIntegrationEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatal("this has to run as root — elevate_linux.go's direct-launch path is what is being asked about")
	}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal("iproute2's ip is not installed, so the routing decision cannot be read")
	}

	proxies, err := mihomoconf.ConvertLinks(
		"vless://11111111-2222-3333-4444-555555555555@198.51.100.1:443?security=tls&type=tcp#Unreachable")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	// The address does not have to answer. Bringing the adapter up and
	// installing its routes is mihomo's own startup work and happens whether or
	// not the one proxy in the group can be reached.
	proxiesYAML, err := mihomoconf.BuildProxiesYAML(proxies, mihomoconf.SplitTunnel{})
	if err != nil {
		t.Fatalf("build proxies: %v", err)
	}

	tun := mihomoconf.DefaultTunOptions()
	// Its own name, so a leftover adapter — or a real WhiteVPN connection on
	// the same machine — is never mistaken for this test's.
	//
	// Fifteen characters at the outside. Linux caps an interface name at
	// IFNAMSIZ-1, and exceeding it fails as ERANGE, which mihomo reports as
	// "configure tun interface: numerical result out of range" — a message that
	// names the stage and not the cause. This test's first name was seventeen
	// characters and cost a full round of CI to explain. The shipped name is
	// eight, so nothing about the product was ever at stake.
	tun.Device = "whitevpn-tuntt"
	if len(tun.Device) > 15 {
		t.Fatalf("device name %q is %d characters; Linux allows 15", tun.Device, len(tun.Device))
	}

	config := mihomoconf.Render(proxiesYAML, mihomoconf.Options{
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

	// The engine's own account of itself, readable on this path because the
	// core is started directly rather than through pkexec. Without it a failure
	// here is "the adapter is not there" and nothing about why.
	engineSaid := &lockedBuffer{}
	proc, err := Spawn(ctx, SpawnOptions{
		CorePath:       requireCore(t),
		WorkingDir:     home,
		ConnectTimeout: 20 * time.Second,
		Stdout:         engineSaid,
		Stderr:         engineSaid,
		// The path being tested. Root already, so this takes elevate_linux.go's
		// direct branch — the same code a desktop session reaches once its own
		// polkit prompt is answered, not one written only for CI.
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
		t.Fatalf("the engine could not read the config: %v", err)
	}
	if err := proc.SetupConfig(ctx, map[string]string{}, "http://198.51.100.1/"); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if err := proc.StartListener(ctx); err != nil {
		t.Fatalf("start listener: %v", err)
	}

	// The adapter is not necessarily there the instant StartListener returns —
	// the same race waitForTunnel covers in production — so it is polled.
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = verifyRealRouteThroughDevice(ipPath, tun.Device); lastErr == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Logf("the engine said:\n%s", engineSaid.String())
	t.Logf("interfaces:\n%s", describeInterfaces(ipPath))
	t.Fatalf("the tunnel never came up: %v", lastErr)
}

// lockedBuffer collects the core's output from whichever goroutine writes it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// describeInterfaces reports what the machine actually has, so a failure says
// whether the adapter was missing or merely not carrying the route.
func describeInterfaces(ipPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ipPath, "-brief", "link", "show").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ip link show failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

// requireCore is corePath without its skip.
//
// corePath is right to stand aside where the engine has not been built — most
// of this package's tests are run by people who have not built it. This one was
// asked for by name, so a missing core is a broken harness and has to say so:
// skipping here is how the first version of this went green while proving
// nothing at all, because the compiled binary was run from a directory where
// the relative path to cores/ resolved outside the repository.
func requireCore(t *testing.T) string {
	t.Helper()
	name := "mihomo-" + runtime.GOOS + "-" + runtime.GOARCH
	path, err := filepath.Abs(filepath.Join("..", "..", "cores", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		cwd, _ := os.Getwd()
		t.Fatalf("the engine binary is not at %s (looked from %s) — build it with `make mihomo-core`, "+
			"and run this from the package directory so the relative path resolves", path, cwd)
	}
	return path
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

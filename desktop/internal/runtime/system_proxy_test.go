package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxSystemProxyGuardGNOMERestoresSnapshot(t *testing.T) {
	t.Setenv("XDG_CURRENT_DESKTOP", "GNOME")
	runner := newFakeSystemProxyRunner()
	runner.seedGNOME()
	runner.gsettings["org.gnome.system.proxy|mode"] = "'none'"
	runner.gsettings["org.gnome.system.proxy.http|host"] = "'old.proxy'"
	runner.gsettings["org.gnome.system.proxy.http|port"] = "8080"

	guard, err := newLinuxSystemProxyGuard(context.Background(), runner.run, "127.0.0.1", 1088)
	if err != nil {
		t.Fatal(err)
	}
	runner.gsettings["org.gnome.system.proxy|mode"] = "'manual'"
	runner.gsettings["org.gnome.system.proxy.http|host"] = "'127.0.0.1'"
	runner.gsettings["org.gnome.system.proxy.http|port"] = "1088"
	if err := guard.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := guard.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}

	if runner.gsettings["org.gnome.system.proxy|mode"] != "'none'" {
		t.Fatalf("expected GNOME mode to be restored, got %q", runner.gsettings["org.gnome.system.proxy|mode"])
	}
	if runner.gsettings["org.gnome.system.proxy.http|host"] != "'old.proxy'" {
		t.Fatalf("expected GNOME host to be restored, got %q", runner.gsettings["org.gnome.system.proxy.http|host"])
	}
	if runner.gsettings["org.gnome.system.proxy.http|port"] != "8080" {
		t.Fatalf("expected GNOME port to be restored, got %q", runner.gsettings["org.gnome.system.proxy.http|port"])
	}
}

func TestLinuxSystemProxyGuardKDERestoresSnapshot(t *testing.T) {
	t.Setenv("XDG_CURRENT_DESKTOP", "KDE")
	runner := newFakeSystemProxyRunner()
	runner.seedKDE()
	runner.kde["ProxyType"] = "0"
	runner.kde["httpProxy"] = "http://old.proxy:8080"

	guard, err := newLinuxSystemProxyGuard(context.Background(), runner.run, "127.0.0.1", 1088)
	if err != nil {
		t.Fatal(err)
	}
	runner.kde["ProxyType"] = "1"
	runner.kde["httpProxy"] = "http://127.0.0.1:1088"
	if err := guard.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := guard.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}

	if runner.kde["ProxyType"] != "0" {
		t.Fatalf("expected KDE proxy type to be restored, got %q", runner.kde["ProxyType"])
	}
	if runner.kde["httpProxy"] != "http://old.proxy:8080" {
		t.Fatalf("expected KDE HTTP proxy to be restored, got %q", runner.kde["httpProxy"])
	}
}

func TestPrepareSystemProxyGuardRejectsUnsupportedLinuxDesktop(t *testing.T) {
	manager := NewManager(Options{
		SystemProxyPlatform: "linux",
		SystemProxyRunner: func(context.Context, string, ...string) (string, error) {
			return "", errors.New("missing command")
		},
	}, Callbacks{})

	_, err := manager.prepareSystemProxyGuard(context.Background(), true, "socks", "127.0.0.1", 1088)
	if err == nil {
		t.Fatal("expected unsupported desktop error")
	}
}

func TestRestoreSystemProxySnapshotFileRestoresLinuxSnapshot(t *testing.T) {
	runner := newFakeSystemProxyRunner()
	runner.seedGNOME()
	snapshot := systemProxySnapshot{
		Platform: "linux",
		Backend:  "gnome",
		Values: map[string]string{
			"org.gnome.system.proxy|mode":      "'none'",
			"org.gnome.system.proxy.http|host": "'old.proxy'",
			"org.gnome.system.proxy.http|port": "8080",
		},
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	raw := []byte(`{"platform":"linux","backend":"gnome","values":{"org.gnome.system.proxy|mode":"'none'","org.gnome.system.proxy.http|host":"'old.proxy'","org.gnome.system.proxy.http|port":"8080"}}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runner.gsettings["org.gnome.system.proxy|mode"] = "'manual'"
	runner.gsettings["org.gnome.system.proxy.http|host"] = "'127.0.0.1'"
	runner.gsettings["org.gnome.system.proxy.http|port"] = "1088"

	if err := restoreSystemProxySnapshotFile(context.Background(), path, "linux", runner.run); err != nil {
		t.Fatal(err)
	}
	for key, value := range snapshot.Values {
		if got := runner.gsettings[key]; got != value {
			t.Fatalf("expected %s=%q, got %q", key, value, got)
		}
	}
}

func TestPrepareSystemProxyGuardSkipsWhenDisabled(t *testing.T) {
	manager := NewManager(Options{SystemProxyPlatform: "linux"}, Callbacks{})
	guard, err := manager.prepareSystemProxyGuard(context.Background(), false, "socks", "127.0.0.1", 1088)
	if err != nil {
		t.Fatal(err)
	}
	if guard != nil {
		t.Fatalf("expected disabled system proxy to skip guard, got %#v", guard)
	}
}

func TestMixedSystemProxyUsesHTTPOnly(t *testing.T) {
	if got := normalizeSystemProxyProtocol("mixed"); got != "http" {
		t.Fatalf("expected mixed system proxy protocol to use http, got %q", got)
	}
	if server := windowsProxyServerValue("127.0.0.1", 1088, normalizeSystemProxyProtocol("mixed")); strings.Contains(server, "socks=") {
		t.Fatalf("expected mixed Windows proxy value to omit socks, got %q", server)
	}

	var commands []string
	guard := macOSSystemProxyGuard{
		runner: func(_ context.Context, _ string, args ...string) (string, error) {
			commands = append(commands, strings.Join(args, " "))
			return "", nil
		},
		expectedHost: "127.0.0.1",
		expectedPort: 1088,
		protocol:     normalizeSystemProxyProtocol("mixed"),
		services:     []string{"Wi-Fi"},
	}
	if err := guard.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if strings.Contains(command, "socksfirewall") {
			t.Fatalf("expected mixed macOS proxy to avoid SOCKS command, got %q", command)
		}
	}
}

type fakeSystemProxyRunner struct {
	gsettings map[string]string
	kde       map[string]string
	calls     []string
}

func newFakeSystemProxyRunner() *fakeSystemProxyRunner {
	return &fakeSystemProxyRunner{
		gsettings: map[string]string{},
		kde:       map[string]string{},
	}
}

func (r *fakeSystemProxyRunner) seedGNOME() {
	for _, key := range gnomeSystemProxyKeys {
		r.gsettings[key] = defaultGSettingsValue(key)
	}
}

func (r *fakeSystemProxyRunner) seedKDE() {
	for _, key := range kdeSystemProxyKeys {
		r.kde[key] = ""
	}
}

func (r *fakeSystemProxyRunner) run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name)
	switch name {
	case "gsettings":
		if len(args) < 3 {
			return "", errors.New("invalid gsettings call")
		}
		key := args[1] + "|" + args[2]
		switch args[0] {
		case "get":
			if len(args) != 3 {
				return "", errors.New("invalid gsettings get call")
			}
			value, ok := r.gsettings[key]
			if !ok {
				return "", errors.New("missing gsettings key")
			}
			return value, nil
		case "set":
			if len(args) != 4 {
				return "", errors.New("invalid gsettings set call")
			}
			r.gsettings[key] = args[3]
			return "", nil
		default:
			return "", errors.New("invalid gsettings action")
		}
	case "kreadconfig6", "kreadconfig5":
		key, ok := kdeConfigKey(args)
		if !ok {
			return "", errors.New("invalid kreadconfig call")
		}
		value, ok := r.kde[key]
		if !ok {
			return "", errors.New("missing kde key")
		}
		return value, nil
	case "kwriteconfig6", "kwriteconfig5":
		key, ok := kdeConfigKey(args)
		if !ok || len(args) == 0 {
			return "", errors.New("invalid kwriteconfig call")
		}
		r.kde[key] = args[len(args)-1]
		return "", nil
	default:
		return "", errors.New("missing command")
	}
}

func defaultGSettingsValue(key string) string {
	switch {
	case key == "org.gnome.system.proxy|mode":
		return "'none'"
	case key == "org.gnome.system.proxy|ignore-hosts":
		return "@as []"
	case key == "org.gnome.system.proxy.http|enabled":
		return "false"
	case key == "org.gnome.system.proxy.http|port" ||
		key == "org.gnome.system.proxy.https|port" ||
		key == "org.gnome.system.proxy.socks|port":
		return "0"
	case key == "org.gnome.system.proxy.http|use-authentication":
		return "false"
	default:
		return "''"
	}
}

func kdeConfigKey(args []string) (string, bool) {
	for idx := 0; idx < len(args)-1; idx++ {
		if args[idx] == "--key" {
			return args[idx+1], true
		}
	}
	return "", false
}

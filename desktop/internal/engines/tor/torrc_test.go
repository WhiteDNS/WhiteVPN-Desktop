package tor

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"whitevpn-desktop/internal/engineprofiles"
)

// Ports of Android's TorEngineConfigTest, with desktop paths.

func nativeDir() string {
	if runtime.GOOS == "windows" {
		return `C:\native`
	}
	return "/native"
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func cfg(mode, transport, bridges string) engineprofiles.TorConfig {
	return engineprofiles.TorConfig{BridgeMode: mode, Transport: transport, Bridges: bridges}
}

func TestManagedTransportPathIsAnUnquotedArgument(t *testing.T) {
	config, err := buildTorrc(cfg("custom", "obfs4", "obfs4 192.0.2.1:443"), nativeDir(), "/data", 1080, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "ClientTransportPlugin obfs4 exec " + filepath.Join(nativeDir(), exe("lyrebird")) + "\n"
	if !strings.Contains(config, want) {
		t.Fatalf("missing %q in:\n%s", want, config)
	}
	bads := []string{nativeDir() + " path", nativeDir() + `"q`, nativeDir() + "'q", nativeDir() + "#x", "native", ""}
	if runtime.GOOS == "windows" {
		bads = append(bads, nativeDir()+`\کاربر`)
	}
	for _, bad := range bads {
		if _, err := buildTorrc(cfg("custom", "", "obfs4 192.0.2.1:443"), bad, "/data", 1080, ""); err == nil {
			t.Errorf("plugin dir %q accepted", bad)
		}
	}
	if _, err := buildTorrc(cfg("custom", "obfs4 exec evil", "obfs4 192.0.2.1:443"), nativeDir(), "/data", 1080, ""); err == nil {
		t.Error("unknown transport accepted")
	}
}

func TestSnowflakeReceivesBrokerAndStunDefaults(t *testing.T) {
	config, err := buildTorrc(cfg("", "snowflake", ""), nativeDir(), "/data", 1080, "snowflake 192.0.2.3:80 fingerprint=example")
	if err != nil {
		t.Fatal(err)
	}
	// lyrebird takes Android's snowflake-client flags as bridge parameters.
	for _, want := range []string{
		"\nClientTransportPlugin snowflake exec " + filepath.Join(nativeDir(), exe("lyrebird")) + "\n",
		"\nBridge snowflake 192.0.2.3:80 fingerprint=example url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("missing %q in:\n%s", want, config)
		}
	}
	if strings.Contains(config, " -url ") {
		t.Error("lyrebird exits on snowflake-client flags")
	}
	config, err = buildTorrc(cfg("custom", "snowflake", "snowflake 192.0.2.3:80 url=https://broker.example/ ice=stun:a:1"), nativeDir(), "/data", 1080, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(config, "\nBridge snowflake 192.0.2.3:80 url=https://broker.example/ ice=stun:a:1 fronts=www.cdn77.com,www.phpmyadmin.net\n") {
		t.Fatalf("bridge's own parameters not kept:\n%s", config)
	}
}

func TestMissingSnowflakeDefaultsAreRejected(t *testing.T) {
	if _, err := buildTorrc(cfg("", "snowflake", ""), nativeDir(), "/data", 1080, ""); err == nil {
		t.Fatal("snowflake without bridges accepted")
	}
}

func TestUnsupportedConjureVariantsAreRejectedBeforeStartup(t *testing.T) {
	for _, option := range []string{"registrar=dns", "registrar=ampcache", "transport=prefix"} {
		if err := validateBridgeCompatibility("conjure", "conjure 192.0.2.1:80 "+option); err == nil {
			t.Errorf("%s accepted", option)
		}
	}
	if err := validateBridgeCompatibility("conjure", "Bridge conjure 192.0.2.1:80 registrar=http transport=min"); err != nil {
		t.Fatal(err)
	}
	if err := validateBridgeCompatibility("obfs4", "conjure 192.0.2.1:80 registrar=dns"); err != nil {
		t.Fatal("non-conjure transport validated conjure options")
	}
	if _, err := buildTorrc(cfg("custom", "conjure", "conjure 192.0.2.1:80 registrar=dns"), nativeDir(), "/data", 1080, ""); err == nil {
		t.Fatal("unsupported conjure registrar reached the torrc")
	}
	config, err := buildTorrc(cfg("default", "conjure", ""), nativeDir(), "/data", 1080, DefaultBridges)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "\nClientTransportPlugin conjure exec "+filepath.Join(nativeDir(), exe("conjure-client"))+"\n") || strings.Count(config, "\nBridge conjure ") != 2 {
		t.Fatalf("got:\n%s", config)
	}
}

func TestDirectModeDoesNotLaunchTransport(t *testing.T) {
	config, err := buildTorrc(cfg("none", "", ""), "", "/data", 1080, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "SocksPort 127.0.0.1:1080\nDataDirectory \"/data\"\nClientOnly 1\nAvoidDiskWrites 1\nLog notice stdout\n"
	if config != want {
		t.Fatalf("got:\n%s", config)
	}
}

func TestCustomBridgesCannotInjectTorDirectives(t *testing.T) {
	config, err := buildTorrc(cfg("custom", "obfs4", "ClientTransportPlugin evil exec /path\nobfs4 192.0.2.1:443"), nativeDir(), "/data", 1080, "")
	if err != nil || strings.Contains(config, "evil") {
		t.Fatalf("directive line not dropped: %v\n%s", err, config)
	}
	for _, bad := range []string{"obfs4 192.0.2.1:443 cert=\"x", "obfs4 192.0.2.1:443 cert=a\\b", "obfs4 192.0.2.1:443\x00"} {
		if _, err := buildTorrc(cfg("custom", "obfs4", bad), nativeDir(), "/data", 1080, ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWrongTransportBridgeIsRejected(t *testing.T) {
	if _, err := buildTorrc(cfg("custom", "obfs4", "snowflake 192.0.2.3:1"), nativeDir(), "/data", 1080, ""); err == nil {
		t.Fatal("snowflake bridge used for obfs4")
	}
}

func TestDefaultBridgesAreFilteredByTransport(t *testing.T) {
	for transport, want := range map[string]int{"obfs4": 16, "snowflake": 2} {
		config, err := buildTorrc(cfg("default", transport, "ignored for default mode"), nativeDir(), "/data", 1080, DefaultBridges)
		if err != nil {
			t.Fatal(err)
		}
		got := 0
		for _, l := range strings.Split(config, "\n") {
			if strings.HasPrefix(l, "Bridge ") {
				got++
				if !strings.HasPrefix(l, "Bridge "+transport+" ") || strings.Contains(l, "\r") {
					t.Errorf("%s: unexpected line", transport)
				}
			}
		}
		if got != want {
			t.Errorf("%s: %d bridges, want %d", transport, got, want)
		}
	}
}

func TestCustomBridgePrefixIsNotDoubled(t *testing.T) {
	config, err := buildTorrc(cfg("custom", "obfs4", "  Bridge obfs4 192.0.2.1:443 cert=x\r\n\r\nobfs4 192.0.2.2:443\r\n"), nativeDir(), "/data", 1080, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(config, "\nBridge obfs4 192.0.2.1:443 cert=x\nBridge obfs4 192.0.2.2:443\n") {
		t.Fatalf("got:\n%s", config)
	}
}

func TestDataDirectoryIsQuoted(t *testing.T) {
	config, err := buildTorrc(cfg("none", "", ""), "", `C:\Users\A "B"\tor`, 1080, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := `DataDirectory "C:\\Users\\A \"B\"\\tor"` + "\n"; !strings.Contains(config, want) {
		t.Fatalf("missing %s in:\n%s", want, config)
	}
}

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

// What follows leans on validateConfig, so it is worth recording what that call
// is actually worth. Measured against this engine, it rejects only input that
// fails to parse into a YAML mapping. It accepts an unknown proxy type, a port
// of 99999, a group naming a proxy that does not exist, duplicate proxy names, a
// rule of gibberish, and an empty document.
//
// So it is a syntax check and nothing more. Running it is still worthwhile — a
// config the engine cannot read at all is worth catching before starting a
// tunnel — but it must never be mistaken for evidence that a config will work.
// That is why connecting has to be confirmed by a real request through the
// proxy rather than by the engine's account of itself, which is what the phone
// app does too.

// TestGeneratedConfigIsReadableByTheEngine checks the weaker of the two claims:
// that what this generator emits is at least parseable by the engine that must
// read it. Whether it carries traffic is a question only a live connection
// answers.
func TestGeneratedConfigIsReadableByTheEngine(t *testing.T) {
	links := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=reality&pbk=cHVibGljLWtleQ&sid=00&fp=chrome&type=tcp&flow=xtls-rprx-vision#Reality%20TCP",
		"vless://11111111-2222-3333-4444-555555555555@b.example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&ed=2048#TLS%20WS",
		"vless://11111111-2222-3333-4444-555555555555@c.example.com:443?security=tls&type=grpc&serviceName=grpcsvc#TLS%20gRPC",
		"trojan://password@d.example.com:443?type=ws&path=%2Ftj&sni=d.example.com#Trojan%20WS",
		"trojan://password@e.example.com:443?sni=e.example.com#Trojan%20TCP",
		"ss://YWVzLTI1Ni1nY206aHVudGVyMg==@f.example.com:8388#Shadowsocks",
	}, "\n")

	proxies, err := mihomoconf.ConvertLinks(links)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	proxiesYAML, err := mihomoconf.BuildProxiesYAML(proxies)
	if err != nil {
		t.Fatalf("build proxies: %v", err)
	}

	// Validation only parses, so the tunnel settings can be exercised here
	// without the privileges that creating one would need.
	config := mihomoconf.Render(proxiesYAML, mihomoconf.Options{
		Secret:     "validation-secret",
		ProxyGroup: mihomoconf.SelectGroup,
		Tun:        mihomoconf.DefaultTunOptions(),
	})

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	proc := spawnReal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proc.Init(ctx, home, 36); err != nil {
		t.Fatalf("initClash: %v", err)
	}
	if err := proc.ValidateConfig(ctx, configPath); err != nil {
		t.Fatalf("the engine could not read our config: %v\n---\n%s", err, config)
	}
}

// The negative control, so the check above is not vacuous. It has to be
// unparseable YAML, because that is the only class of fault this call detects.
func TestEngineRejectsUnparseableConfig(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	unparseable := "mixed-port: 2080\nproxies:\n  - name: [unclosed\n"
	if err := os.WriteFile(configPath, []byte(unparseable), 0o600); err != nil {
		t.Fatal(err)
	}

	proc := spawnReal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proc.Init(ctx, home, 36); err != nil {
		t.Fatalf("initClash: %v", err)
	}
	if err := proc.ValidateConfig(ctx, configPath); err == nil {
		t.Fatal("unparseable YAML was accepted, so validation is not being exercised")
	}
}

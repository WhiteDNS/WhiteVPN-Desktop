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

// A chain is only real if the engine reads it. The generated shape leans on two
// things being true of mihomo — that dialer-proxy may name a proxy group, and
// that a group and a proxy share one namespace — and neither is worth assuming
// from reading the source alone.
func TestTheEngineReadsAChainedConfig(t *testing.T) {
	links := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&type=ws&path=%2Fws#First%20Hop",
		"trojan://password@b.example.com:443?sni=b.example.com#Second%20Hop",
		"vless://11111111-2222-3333-4444-555555555555@c.example.com:443?security=tls&type=grpc&serviceName=svc#Another",
	}, "\n")

	proxies, err := mihomoconf.ConvertLinks(links)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	proxiesYAML, _, err := mihomoconf.BuildProxiesYAMLWithChain(proxies, mihomoconf.SplitTunnel{}, mihomoconf.Chain{ExitNode: "Second Hop"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		"dialer-proxy: " + mihomoconf.SelectGroup,
		"MATCH," + mihomoconf.ChainExitName,
	} {
		if !strings.Contains(proxiesYAML, want) {
			t.Fatalf("the chain is not in the config (%q missing):\n%s", want, proxiesYAML)
		}
	}

	config := mihomoconf.Render(proxiesYAML, mihomoconf.Options{
		Secret:     "validation-secret",
		ProxyGroup: mihomoconf.SelectGroup,
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
		t.Fatalf("the engine rejected the chained config: %v\n---\n%s", err, config)
	}
}

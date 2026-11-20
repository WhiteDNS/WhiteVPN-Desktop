package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/warp"
)

// The 1.8.0-beta.2 shape, read by the pinned core: WARP (with its DPI noise) as
// node 1, a CDN TLS link as node 2 carrying automatic optional ECH. `optional`
// only exists in the v1.19.34 fork, so this is what catches a stale core.
func TestTheEngineReadsWarpChainWithAutomaticECH(t *testing.T) {
	keys, err := warp.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	body, err := warp.Config{
		Server: "162.159.192.1", Port: 2408,
		PrivateKey: keys.PrivateKey, PublicKey: warp.CloudflarePublicKey,
		IPv4: "172.16.0.2", IPv6: "2606:4700:110:8a36::1",
		Reserved: []int{1, 2, 3}, Noise: true,
	}.YAML()
	if err != nil {
		t.Fatalf("warp yaml: %v", err)
	}
	warpProxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		t.Fatalf("parse warp: %v", err)
	}
	links, err := mihomoconf.ConvertLinks("vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443?security=tls&type=ws&sni=cdn.example.com&path=%2Fws#Exit")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	planned, chain, err := mihomoconf.PlanChain(
		[]mihomoconf.ChainSource{{ID: "warp", Name: "WARP", Proxies: warpProxies}, {ID: "pub", Name: "Public", Proxies: links}},
		mihomoconf.ChainHop{Ref: mihomoconf.ChainRef{SubscriptionID: "warp", Node: warp.ProxyName}},
		mihomoconf.ChainHop{Ref: mihomoconf.ChainRef{SubscriptionID: "pub", Node: "Exit"}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	planned = mihomoconf.ApplyAutoECH(planned, true)
	proxiesYAML, _, err := mihomoconf.BuildProxiesYAMLWithRouting(planned, mihomoconf.Routing{Chain: chain})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{"optional: true", "wireguard-dpi-option", "dialer-proxy: " + mihomoconf.SelectGroup} {
		if !strings.Contains(proxiesYAML, want) {
			t.Fatalf("%q missing from the config:\n%s", want, proxiesYAML)
		}
	}

	config := mihomoconf.Render(proxiesYAML, mihomoconf.Options{Secret: "validation-secret", ProxyGroup: mihomoconf.SelectGroup})
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
		t.Fatalf("the engine rejected the release config: %v\n---\n%s", err, config)
	}
}

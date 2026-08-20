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

// The reason the pinned core moved to v1.19.30.
//
// v1.19.29's AmneziaWGOption had no Version field at all, so `version: 3` was
// not a setting that did nothing — mihomo decodes this map into a struct and
// rejects keys it has no field for, which fails the whole config rather than
// the one proxy. This asks the engine that actually ships whether it reads
// what the link parser now emits.
func TestTheEngineReadsAmneziaWGv3(t *testing.T) {
	link := "wireguard://cHJpdmF0ZS1rZXktMzItYnl0ZXMtZm9yLXRlc3Rz@a.example.com:51820" +
		"?publickey=cHVibGljLWtleS0zMi1ieXRlcy1mb3ItdGVzdHM&address=10.0.0.2/32" +
		"&jc=4&jmin=40&jmax=70&s1=15&s2=25&s3=5&s4=5" +
		"&h1=1111111111&h2=2222222222&h3=3333333333&h4=4444444444#AmneziaWG"

	proxies, err := mihomoconf.ConvertLinks(link)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	options, ok := proxies[0]["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatalf("the link parser emitted no Amnezia options: %#v", proxies[0])
	}
	// Written here rather than by the parser: `version` arrives with the core
	// that has the field, and this is the test that says the core does.
	options["version"] = 3

	proxiesYAML, err := mihomoconf.BuildProxiesYAML(proxies, mihomoconf.SplitTunnel{})
	if err != nil {
		t.Fatalf("build proxies: %v", err)
	}
	config := mihomoconf.Render(proxiesYAML, mihomoconf.Options{
		Secret:     "validation-secret",
		ProxyGroup: mihomoconf.SelectGroup,
	})
	if !strings.Contains(config, "version: 3") {
		t.Fatalf("the rendered config does not carry the version:\n%s", config)
	}

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
		t.Fatalf("the engine rejected AmneziaWG v3, so the core bump did not deliver it: %v\n---\n%s", err, config)
	}
}

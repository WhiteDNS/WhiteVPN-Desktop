package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/profiles"
)

func TestImportClipboardConfigurationUsesLocalSubscription(t *testing.T) {
	a := newSnapshotTestApp(t)
	a.store = profiles.NewStore(filepath.Join(a.configDir, "state.json"))
	for _, invalid := range []string{" ", "not a configuration", strings.Repeat("a", v2raySubscriptionMaxBytes+1)} {
		if _, err := a.importLocalSubscription("", invalid); err == nil || len(a.state.V2RaySubscriptions) != 0 {
			t.Fatal("invalid clipboard text changed the subscriptions")
		}
	}
	body := "proxies:\n  - name: MASQUE Nav\n    type: masque\n    server: 192.0.2.2\n    port: 443\n    network: h2\n    private-key: clipboard-test-key"
	state, err := a.importLocalSubscription("", body)
	if err != nil {
		t.Fatal(err)
	}
	sub := state.V2RaySubscriptions[len(state.V2RaySubscriptions)-1]
	if !sub.LocalConfig || !sub.Inline || sub.Body != "" || sub.ImportedCount != 1 || sub.Name == "" {
		t.Fatal("unexpected public metadata for clipboard configuration")
	}
	if got, err := a.fetchSubscriptionBodyFor(context.Background(), sub.ID); err != nil || got != body {
		t.Fatal("clipboard configuration is unavailable to the connection path")
	}
}

func TestImportSubscriptionFile(t *testing.T) {
	a := newSnapshotTestApp(t)
	a.store = profiles.NewStore(filepath.Join(a.configDir, "state.json"))
	body := "proxies:\n  - name: MASQUE Nav\n    type: masque\n    server: 192.0.2.2\n    port: 443\n    network: h2\n    private-key: test-key"
	path := filepath.Join(a.configDir, "WARP MASQUE.yaml")
	if err := os.WriteFile(path, []byte("\uFEFF"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := a.importSubscriptionFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sub := state.V2RaySubscriptions[len(state.V2RaySubscriptions)-1]
	if sub.Name != "WARP MASQUE" || !sub.LocalConfig || !sub.Inline || sub.Body != "" || sub.ImportedCount != 1 {
		t.Fatal("unexpected public metadata for the imported file")
	}
	if err := os.WriteFile(path, []byte("not a subscription"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.importSubscriptionFile(path); err == nil || len(a.state.V2RaySubscriptions) != len(state.V2RaySubscriptions) {
		t.Fatal("invalid file changed the subscriptions")
	}
	loaded, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := findV2RaySubscription(loaded, sub.ID)
	if !ok || !stored.LocalConfig || stored.Body != body {
		t.Fatal("imported configuration did not survive a reload")
	}
	nodes, err := a.ListSubscriptionNodes(sub.ID, false)
	if err != nil || len(nodes.Nodes) != 1 || nodes.Nodes[0].Type != "masque" {
		t.Fatalf("imported node is unavailable: %v", err)
	}
	if got, err := a.fetchSubscriptionBodyFor(context.Background(), sub.ID); err != nil || got != body {
		t.Fatal("the connection path did not resolve the imported configuration")
	}
}

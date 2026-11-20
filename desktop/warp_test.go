package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/warp"
)

const warpTestResponse = `{"config":{"client_id":"AQID",
  "peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","endpoint":{"v4":"162.159.192.5:0"}}],
  "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8a36::1"}}}}`

func warpTestApp(t *testing.T, status int) *App {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, warpTestResponse)
	}))
	t.Cleanup(server.Close)
	previous := warpRegisterURL
	warpRegisterURL = server.URL
	t.Cleanup(func() { warpRegisterURL = previous })
	a := newSnapshotTestApp(t)
	a.store = profiles.NewStore(filepath.Join(a.configDir, "state.json"))
	return a
}

func TestAddWarpSubscriptionStoresAUsableSubscriptionWithoutExposingTheKey(t *testing.T) {
	a := warpTestApp(t, http.StatusOK)
	state, err := a.AddWarpSubscription()
	if err != nil {
		t.Fatal(err)
	}
	var public model.V2RaySubscription
	for _, sub := range state.V2RaySubscriptions {
		if sub.Name == warp.ProxyName {
			public = sub
		}
	}
	if public.ID == "" || !public.Inline || public.Body != "" || model.IsBuiltInSubscription(public.ID) {
		t.Fatalf("public subscription = %#v", public)
	}

	stored, ok := findV2RaySubscription(a.state, public.ID)
	config, isWarp := warp.Parse(stored.Body)
	if !ok || !isWarp || config.PrivateKey == "" {
		t.Fatalf("stored body is not WARP: %q", stored.Body)
	}
	assertNoWarpKey := func(what string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), config.PrivateKey) {
			t.Fatalf("%s carries the private key", what)
		}
	}
	assertNoWarpKey("public state", a.GetAppState())
	edit, err := a.GetV2RaySubscriptionForEdit(public.ID)
	if err != nil || !edit.Inline {
		t.Fatalf("subscription editor = %#v, %v", edit, err)
	}
	assertNoWarpKey("subscription editor", edit)
	settings, err := a.GetWarpSettings(public.ID)
	if err != nil || settings != (WarpSettings{Name: "WARP", Server: "162.159.192.5", Port: 2408, Noise: true}) {
		t.Fatalf("WARP settings = %#v, %v", settings, err)
	}

	// It is a normal subscription to the rest of the app: the body resolves,
	// and the desktop's own parser and config builder take it.
	body, err := a.fetchSubscriptionBodyFor(context.Background(), public.ID)
	if err != nil || body != stored.Body {
		t.Fatalf("body = %q, %v", body, err)
	}
	nodes, err := whiteVPNNodesFromSubscription(body)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "WARP" {
		t.Fatalf("nodes = %#v, %v", nodes, err)
	}
	assertNoWarpKey("node list", nodes)
	proxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := mihomoconf.BuildProxiesYAML(proxies, mihomoconf.SplitTunnel{})
	if err != nil || !strings.Contains(rendered, "wireguard-dpi-option") || !strings.Contains(rendered, "type: wireguard") {
		t.Fatalf("engine config lost the WARP proxy: %v\n%s", err, rendered)
	}

	loaded, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persisted, _ := findV2RaySubscription(loaded, public.ID); persisted.Body != stored.Body {
		t.Fatal("the WARP body did not survive a reload")
	}
	assertNoWarpKey("backup", loaded.BackupState())
}

func TestSaveWarpSettingsChangesOnlyServerPortAndNoise(t *testing.T) {
	a := warpTestApp(t, http.StatusOK)
	if _, err := a.AddWarpSubscription(); err != nil {
		t.Fatal(err)
	}
	id := a.state.V2RaySubscriptions[len(a.state.V2RaySubscriptions)-1].ID
	before, _ := warp.Parse(a.state.V2RaySubscriptions[len(a.state.V2RaySubscriptions)-1].Body)

	for _, bad := range []WarpSettings{
		{Name: "WARP", Server: "1.1.1.1\n  type: x", Port: 2408},
		{Name: "WARP", Server: "1.1.1.1", Port: 0},
		{Name: " ", Server: "1.1.1.1", Port: 2408},
	} {
		if _, err := a.SaveWarpSettings(id, bad); err == nil {
			t.Fatalf("saved %#v", bad)
		}
	}
	if _, err := a.SaveWarpSettings(id, WarpSettings{Name: "My WARP", Server: "188.114.97.3", Port: 894, Noise: false}); err != nil {
		t.Fatal(err)
	}
	sub, _ := findV2RaySubscription(a.state, id)
	after, ok := warp.Parse(sub.Body)
	if !ok || sub.Name != "My WARP" {
		t.Fatalf("saved subscription = %#v", sub)
	}
	want := before
	want.Server, want.Port, want.Noise = "188.114.97.3", 894, false
	if after.Server != want.Server || after.Port != want.Port || after.Noise || after.PrivateKey != before.PrivateKey ||
		after.PublicKey != before.PublicKey || after.IPv4 != before.IPv4 || after.IPv6 != before.IPv6 || len(after.Reserved) != 3 {
		t.Fatalf("edit = %#v, want %#v", after, want)
	}

	// A subscription fetched from a URL has no WARP editor.
	a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, model.V2RaySubscription{ID: "url", Name: "x", URL: "https://example.com/sub"})
	if _, err := a.GetWarpSettings("url"); err == nil {
		t.Fatal("a URL subscription opened as WARP")
	}
}

func TestAddWarpSubscriptionReportsFailureAndAddsNothing(t *testing.T) {
	a := warpTestApp(t, http.StatusInternalServerError)
	count := len(a.state.V2RaySubscriptions)
	if _, err := a.AddWarpSubscription(); err == nil {
		t.Fatal("expected an error")
	}
	if len(a.state.V2RaySubscriptions) != count {
		t.Fatal("a failed registration added a subscription")
	}
}

package main

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
	"whitevpn-desktop/internal/warp"
)

// warpAndPublicApp is a WARP subscription, as the WARP button stores it, next
// to a provider serving share links.
func warpAndPublicApp(t *testing.T) *App {
	t.Helper()
	body, err := warp.Config{Server: "162.159.192.5", Port: warp.DefaultPort, PrivateKey: "cHJpdmF0ZQ==",
		PublicKey: warp.CloudflarePublicKey, IPv4: "172.16.0.2", Noise: true}.YAML()
	if err != nil {
		t.Fatal(err)
	}
	links := link("11111111-1111-1111-1111-111111111111", "pub.example.com", "Public") +
		"\nsocks5://tcp.example.com:1080?udp=false#TCP%20Only"
	app := twoProviderApp(t, links, links)
	app.mu.Lock()
	app.state.V2RaySubscriptions[1] = model.V2RaySubscription{ID: "warp", Name: "WARP", Body: body}
	app.mu.Unlock()
	return app
}

func renderedProxy(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	proxies, _ := document["proxies"].([]any)
	for _, entry := range proxies {
		if proxy, _ := entry.(map[string]any); proxy["name"] == name {
			return proxy
		}
	}
	t.Fatalf("no proxy %q", name)
	return nil
}

// The combination the help text suggests: WARP as node 1, a public config as
// node 2, from two different subscriptions, through to the engine's config.
func TestWARPAsNode1WithALinkNode2(t *testing.T) {
	app := warpAndPublicApp(t)
	chain := model.ChainSettings{
		Entry: model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: "warp", Node: "WARP"},
		Exit:  model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: "one", Node: "Public"},
	}
	body, plan, err := app.chainSubscription(context.Background(), chain)
	if err != nil {
		t.Fatal(err)
	}
	config, firstHop, err := session.PrepareConfig(session.Options{Subscription: body, Chain: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(firstHop) != 1 || firstHop[0] != "WARP" {
		t.Fatalf("node 1 should be WARP alone: %v", firstHop)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(config), &document); err != nil {
		t.Fatal(err)
	}
	if warpProxy := renderedProxy(t, document, "WARP"); warpProxy["type"] != "wireguard" || warpProxy["dialer-proxy"] != nil {
		t.Fatalf("WARP should be dialled directly: %v", warpProxy)
	}
	exit := renderedProxy(t, document, mihomoconf.ChainExitName)
	if exit["server"] != "pub.example.com" || exit["dialer-proxy"] != mihomoconf.SelectGroup {
		t.Fatalf("the public config should leave through WARP: %v", exit)
	}
	if !strings.Contains(config, "MATCH,"+mihomoconf.ChainExitName) {
		t.Fatal("traffic does not leave through node 2")
	}

	// WARP behind a node 1 that carries no UDP cannot work, and is refused
	// with the reason.
	chain.Exit = chain.Entry
	chain.Entry = model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: "one", Node: "TCP Only"}
	if _, _, err := app.chainSubscription(context.Background(), chain); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("expected the UDP reason, got %v", err)
	}
}

// The picker lists both subscriptions, the user's own marked as such, and
// says why a config cannot be node 2 next to a fixed TCP-only node 1.
func TestChainOptionsMarkWhatCannotBeChosen(t *testing.T) {
	app := warpAndPublicApp(t)
	if _, err := app.SaveConnectionChain(model.ChainSettings{
		Entry: model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: "one", Node: "TCP Only"},
	}); err != nil {
		t.Fatal(err)
	}
	options, err := app.ListChainOptions(model.ChainSlotExit)
	if err != nil {
		t.Fatal(err)
	}
	if options.Incomplete || len(options.Groups) != 2 {
		t.Fatalf("expected both lists: %+v", options)
	}
	for _, group := range options.Groups {
		if !group.UserMade {
			t.Errorf("%s is the user's own", group.Name)
		}
		switch group.SubscriptionID {
		case "warp":
			if group.Issues["WARP"] != string(mihomoconf.ChainIssueUDP) {
				t.Errorf("WARP needs UDP from node 1: %v", group.Issues)
			}
		case "one":
			if group.Issues["TCP Only"] != string(mihomoconf.ChainIssueSame) || group.Issues["Public"] != "" {
				t.Errorf("node 1 cannot also be node 2, and a TCP node 2 needs nothing: %v", group.Issues)
			}
		}
	}

	// An Automatic node 1 rules nothing out.
	if _, err := app.SaveConnectionChain(model.DefaultChainSettings()); err != nil {
		t.Fatal(err)
	}
	options, err = app.ListChainOptions(model.ChainSlotExit)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range options.Groups {
		if len(group.Issues) != 0 {
			t.Errorf("%s: nothing should be marked: %v", group.Name, group.Issues)
		}
	}
}

// The All row is the merged list, not one of its sources; reading it as one
// would have All fetch itself.
func TestAllIsNotOneOfItsOwnSources(t *testing.T) {
	app := twoProviderApp(t, "", "")
	app.mu.Lock()
	app.state.V2RaySubscriptions = append(app.state.V2RaySubscriptions,
		model.V2RaySubscription{ID: model.AllSubscriptionsID, Name: "All"})
	app.mu.Unlock()
	for _, source := range app.everySubscriptionSource() {
		if model.IsEverySubscription(source.id) {
			t.Fatal("All lists itself as a source")
		}
	}
}

// A settings save from the form cannot overwrite the chain: the picker saves
// it on its own, and the form may hold an older copy.
func TestSettingsSaveKeepsTheChain(t *testing.T) {
	app := twoProviderApp(t, "", "")
	chain := model.ChainSettings{Entry: model.ChainHop{Mode: model.ChainHopAutomatic}, Exit: model.ChainHop{Mode: model.ChainHopAutomatic}}
	if _, err := app.SaveConnectionChain(chain); err != nil {
		t.Fatal(err)
	}
	form := app.GetWhiteVPNSettingsForEdit()
	form.Chain = model.DefaultChainSettings()
	state, err := app.SaveWhiteVPNSettings(form)
	if err != nil {
		t.Fatal(err)
	}
	if state.WhiteVPN.Chain != chain {
		t.Fatalf("the form undid the chain: %+v", state.WhiteVPN.Chain)
	}
}

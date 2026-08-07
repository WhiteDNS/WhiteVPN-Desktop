package main

import (
	"path/filepath"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/session"
)

const subscriptionLinks = "vless://11111111-2222-3333-4444-555555555555@one.example.com:443?security=reality&pbk=k&sid=00#Alpha\n" +
	"trojan://password@two.example.com:443?sni=two.example.com#Beta\n" +
	"trojan://password@three.example.com:443?sni=three.example.com#Gamma"

func hiddenNodesApp(t *testing.T) *App {
	t.Helper()
	state := model.DefaultAppState()
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}
	nodes, err := whiteVPNNodesFromSubscription(subscriptionLinks)
	if err != nil {
		t.Fatal(err)
	}
	app.storeWhiteVPNNodes("sub-1", nodes, time.Now().UTC())
	return app
}

func nodeNamed(t *testing.T, list model.WhiteVPNNodeList, name string) model.WhiteVPNNode {
	t.Helper()
	for _, node := range list.Nodes {
		if node.Name == name {
			return node
		}
	}
	t.Fatalf("node %q is not in the list", name)
	return model.WhiteVPNNode{}
}

// Hidden, not deleted: the node stays in the list carrying a flag, because one
// removed outright could never be put back.
func TestHidingANodeFlagsItRatherThanDroppingIt(t *testing.T) {
	app := hiddenNodesApp(t)

	list, err := app.SetNodesHidden("sub-1", []string{"Beta"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 3 {
		t.Fatalf("the node should still be listed, got %d", len(list.Nodes))
	}
	if !nodeNamed(t, list, "Beta").Hidden {
		t.Fatal("Beta should be marked hidden")
	}
	if nodeNamed(t, list, "Alpha").Hidden {
		t.Fatal("Alpha should be untouched")
	}
}

func TestHidingIsReversible(t *testing.T) {
	app := hiddenNodesApp(t)
	if _, err := app.SetNodesHidden("sub-1", []string{"Beta"}, true); err != nil {
		t.Fatal(err)
	}
	list, err := app.SetNodesHidden("sub-1", []string{"Beta"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if nodeNamed(t, list, "Beta").Hidden {
		t.Fatal("Beta should be visible again")
	}
	if names := app.hiddenNodeNames("sub-1"); len(names) != 0 {
		t.Fatalf("nothing should be left hidden, got %v", names)
	}
}

// The point of holding these by name: a refresh drops every profile a
// subscription produced and re-imports with new ids, so anything keyed by id
// would come undone exactly when it needs to survive.
func TestHidingSurvivesARefreshOfTheNodeList(t *testing.T) {
	app := hiddenNodesApp(t)
	if _, err := app.SetNodesHidden("sub-1", []string{"Gamma"}, true); err != nil {
		t.Fatal(err)
	}

	// What a refresh does: the cache is dropped and the list rebuilt from the
	// subscription body.
	app.forgetWhiteVPNNodes("sub-1")
	nodes, err := whiteVPNNodesFromSubscription(subscriptionLinks)
	if err != nil {
		t.Fatal(err)
	}
	app.markHiddenNodes("sub-1", nodes)
	list := app.storeWhiteVPNNodes("sub-1", nodes, time.Now().UTC())

	if !nodeNamed(t, list, "Gamma").Hidden {
		t.Fatal("hiding did not survive the refresh")
	}
}

// Hidden from the list but still connectable would be the worst of both.
func TestHiddenNodesNeverReachTheEngineConfig(t *testing.T) {
	document, candidates, err := session.PrepareConfig(session.Options{
		Subscription: subscriptionLinks,
		Exclude:      []string{"Beta"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range candidates {
		if name == "Beta" {
			t.Fatal("a hidden node is still selectable")
		}
	}
	if len(candidates) != 2 {
		t.Fatalf("expected the other two nodes, got %v", candidates)
	}
	// Not merely unpreferred — gone, so the engine's url-test group cannot pick
	// it either.
	if contains(document, "Beta") {
		t.Fatal("a hidden node is still in the configuration")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// Hiding the last node would leave the engine nothing to build from, and the
// failure would surface later as an error about a missing group.
func TestHidingEverythingIsRefused(t *testing.T) {
	app := hiddenNodesApp(t)
	if _, err := app.SetNodesHidden("sub-1", []string{"Alpha", "Beta", "Gamma"}, true); err == nil {
		t.Fatal("expected hiding every node to be refused")
	}
	if names := app.hiddenNodeNames("sub-1"); len(names) != 0 {
		t.Fatalf("the refused change was stored anyway: %v", names)
	}
}

func TestPreferredNodeNamesSkipsHiddenNodes(t *testing.T) {
	nodes, err := whiteVPNNodesFromSubscription(subscriptionLinks)
	if err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		if nodes[i].Name == "Beta" {
			nodes[i].Hidden = true
		}
	}

	settings := model.NormalizeWhiteVPNSettings(model.WhiteVPNSettings{})
	settings.Connection.Types = []string{"trojan"}
	names := preferredNodeNames(nodes, settings)
	for _, name := range names {
		if name == "Beta" {
			t.Fatalf("a hidden node was preferred: %v", names)
		}
	}

	// And naming one directly finds nothing rather than naming a node the engine
	// does not hold.
	settings = model.NormalizeWhiteVPNSettings(model.WhiteVPNSettings{})
	settings.Connection.Node = "Beta"
	if names := preferredNodeNames(nodes, settings); len(names) != 0 {
		t.Fatalf("expected a hidden node to be unavailable, got %v", names)
	}
}

// A document-shaped subscription carries no share links, so there is nothing to
// copy and the reason is worth saying.
func TestCopyingANodeWithoutALinkExplainsItself(t *testing.T) {
	app := hiddenNodesApp(t)
	nodes := app.whiteVPNNodesSnapshot("sub-1")
	for i := range nodes {
		nodes[i].Link = ""
	}
	app.storeWhiteVPNNodes("sub-1", nodes, time.Now().UTC())

	_, err := app.CopyNodeToManual("sub-1", "Alpha")
	if err == nil {
		t.Fatal("expected copying a node with no link to be refused")
	}
	if !contains(err.Error(), "configuration file") {
		t.Fatalf("the reason should say why: %v", err)
	}
}

func TestCopyingANodeAddsItToTheManualConfigs(t *testing.T) {
	app := hiddenNodesApp(t)

	if _, err := app.CopyNodeToManual("sub-1", "Alpha"); err != nil {
		t.Fatal(err)
	}
	manual := app.manualProfiles()
	if len(manual) != 1 {
		t.Fatalf("expected one manual config, got %d", len(manual))
	}
	if manual[0].Server != "one.example.com" {
		t.Fatalf("the wrong node was copied: %#v", manual[0])
	}
	// A copy is the user's own, so a refresh of the subscription cannot touch it.
	if manual[0].SubscriptionID != "" {
		t.Fatalf("a copied node should not belong to the subscription: %q", manual[0].SubscriptionID)
	}
}

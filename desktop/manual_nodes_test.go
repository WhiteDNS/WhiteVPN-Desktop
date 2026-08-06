package main

import (
	"path/filepath"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func manualNodesApp(t *testing.T, items ...model.V2RayProfile) *App {
	t.Helper()
	state := model.DefaultAppState()
	state.V2RayProfiles = items
	state.SelectedSubscriptionID = model.ManualServerSourceID
	return &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}
}

func manualProfile(id, name, server string) model.V2RayProfile {
	return model.V2RayProfile{
		ID:         id,
		Name:       name,
		Protocol:   model.V2RayProtocolVLESS,
		Server:     server,
		ServerPort: 443,
		UUID:       "11111111-1111-1111-1111-111111111111",
		Network:    "tcp",
		TLS:        true,
	}
}

// A row can only be edited if it knows which stored config it came from. The
// match is on the share link rather than on position, because the exporter skips
// profiles it cannot express and the parser skips proxies it cannot use — on
// position, one incomplete profile shifts every row after it onto the wrong
// config, and the delete button removes something else.
func TestManualNodesCarryTheProfileTheyCameFrom(t *testing.T) {
	first := manualProfile("v2ray-1", "First", "one.example.com")
	second := manualProfile("v2ray-2", "Second", "two.example.com")
	app := manualNodesApp(t, first, second)

	list, err := app.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 2 {
		t.Fatalf("expected both configs listed, got %d", len(list.Nodes))
	}

	byServer := map[string]string{}
	for _, node := range list.Nodes {
		byServer[node.Server] = node.ProfileID
	}
	if byServer["one.example.com"] != first.ID {
		t.Fatalf("first node points at %q, not %q", byServer["one.example.com"], first.ID)
	}
	if byServer["two.example.com"] != second.ID {
		t.Fatalf("second node points at %q, not %q", byServer["two.example.com"], second.ID)
	}
}

// A profile that cannot be exported is skipped by the exporter, so the node
// after it must not inherit its identity.
func TestManualNodeIdentitySurvivesAnIncompleteProfile(t *testing.T) {
	broken := manualProfile("v2ray-broken", "Broken", "")
	good := manualProfile("v2ray-good", "Good", "good.example.com")
	app := manualNodesApp(t, broken, good)

	list, err := app.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 1 {
		t.Fatalf("only the exportable config should be listed, got %d", len(list.Nodes))
	}
	if list.Nodes[0].ProfileID != good.ID {
		t.Fatalf("the surviving node points at %q, not %q", list.Nodes[0].ProfileID, good.ID)
	}
}

// Nodes from the catalogue or a subscription are a reading of what a provider is
// serving. They return unchanged at the next refresh, so they carry no profile
// and the interface offers no edit or delete for them.
func TestSubscriptionNodesCarryNoProfile(t *testing.T) {
	fromSubscription := manualProfile("v2ray-sub", "Theirs", "theirs.example.com")
	fromSubscription.SubscriptionID = "sub-1"
	app := manualNodesApp(t, fromSubscription, manualProfile("v2ray-mine", "Mine", "mine.example.com"))

	list, err := app.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 1 || list.Nodes[0].Server != "mine.example.com" {
		t.Fatalf("the manual source should hold only manual configs, got %#v", list.Nodes)
	}
}

func TestSaveManualNodeChangesTheStoredConfig(t *testing.T) {
	profile := manualProfile("v2ray-1", "Before", "before.example.com")
	app := manualNodesApp(t, profile)

	edited := profile
	edited.Name = "After"
	edited.Server = "after.example.com"
	edited.ServerPort = 8443

	list, err := app.SaveManualNode(edited)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 1 {
		t.Fatalf("expected one config, got %d", len(list.Nodes))
	}
	if list.Nodes[0].Server != "after.example.com" || list.Nodes[0].Port != 8443 {
		t.Fatalf("the edit did not reach the list: %#v", list.Nodes[0])
	}
	// The returned list is rebuilt rather than served from the cache, or the row
	// would keep showing the old details until the cache expired.
	if list.Nodes[0].ProfileID != profile.ID {
		t.Fatalf("the edited row lost its profile: %#v", list.Nodes[0])
	}
}

// Storing a config the engine cannot be built from would put a row on the page
// that fails at connect with no clue as to why.
func TestSaveManualNodeRefusesAnIncompleteConfig(t *testing.T) {
	profile := manualProfile("v2ray-1", "Fine", "fine.example.com")
	app := manualNodesApp(t, profile)

	broken := profile
	broken.Server = ""
	if _, err := app.SaveManualNode(broken); err == nil {
		t.Fatal("expected a config with no server to be refused")
	}
	if stored, _ := app.manualProfileByID(profile.ID); stored.Server != "fine.example.com" {
		t.Fatalf("the refused edit was stored anyway: %#v", stored)
	}
}

func TestSaveManualNodeRefusesASubscriptionConfig(t *testing.T) {
	theirs := manualProfile("v2ray-sub", "Theirs", "theirs.example.com")
	theirs.SubscriptionID = "sub-1"
	app := manualNodesApp(t, theirs)

	edited := theirs
	edited.Name = "Mine now"
	if _, err := app.SaveManualNode(edited); err == nil {
		t.Fatal("expected a subscription's config to be refused")
	}
}

func TestDeleteManualNodesRemovesThem(t *testing.T) {
	first := manualProfile("v2ray-1", "First", "one.example.com")
	second := manualProfile("v2ray-2", "Second", "two.example.com")
	third := manualProfile("v2ray-3", "Third", "three.example.com")
	app := manualNodesApp(t, first, second, third)

	list, err := app.DeleteManualNodes([]string{first.ID, third.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 1 || list.Nodes[0].Server != "two.example.com" {
		t.Fatalf("expected only the second config left, got %#v", list.Nodes)
	}
	if _, ok := app.manualProfileByID(first.ID); ok {
		t.Fatal("the first config is still stored")
	}
}

// Deleting the last one legitimately empties the list, which must not read as a
// failure to build it.
func TestDeleteManualNodesCanEmptyTheList(t *testing.T) {
	only := manualProfile("v2ray-1", "Only", "only.example.com")
	app := manualNodesApp(t, only)

	list, err := app.DeleteManualNodes([]string{only.ID})
	if err != nil {
		t.Fatalf("emptying the list should not be an error: %v", err)
	}
	if len(list.Nodes) != 0 {
		t.Fatalf("expected an empty list, got %#v", list.Nodes)
	}
}

func TestDeleteManualNodesRefusesASubscriptionConfig(t *testing.T) {
	theirs := manualProfile("v2ray-sub", "Theirs", "theirs.example.com")
	theirs.SubscriptionID = "sub-1"
	app := manualNodesApp(t, theirs)

	if _, err := app.DeleteManualNodes([]string{theirs.ID}); err == nil {
		t.Fatal("expected a subscription's config to be refused")
	}
	if _, ok := app.manualProfileByID(theirs.ID); !ok {
		t.Fatal("the refused deletion happened anyway")
	}
}

// A config carrying traffic cannot vanish from underneath the connection.
func TestDeleteManualNodesRefusesTheConnectedConfig(t *testing.T) {
	profile := manualProfile("v2ray-1", "Live", "live.example.com")
	app := manualNodesApp(t, profile)

	list, err := app.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	app.state.Runtime.Status = model.RuntimeConnected
	app.state.Runtime.NodeName = list.Nodes[0].Name
	app.mu.Unlock()

	if _, err := app.DeleteManualNodes([]string{profile.ID}); err == nil {
		t.Fatal("expected the connected config to be refused")
	}
	if _, ok := app.manualProfileByID(profile.ID); !ok {
		t.Fatal("the connected config was deleted anyway")
	}
}

func TestManualNodeProfileOpensTheStoredConfig(t *testing.T) {
	profile := manualProfile("v2ray-1", "Mine", "mine.example.com")
	theirs := manualProfile("v2ray-sub", "Theirs", "theirs.example.com")
	theirs.SubscriptionID = "sub-1"
	app := manualNodesApp(t, profile, theirs)

	found, err := app.ManualNodeProfile(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if found.Server != "mine.example.com" {
		t.Fatalf("wrong config returned: %#v", found)
	}
	if _, err := app.ManualNodeProfile(theirs.ID); err == nil {
		t.Fatal("expected a subscription's config not to be editable")
	}
	if _, err := app.ManualNodeProfile("gone"); err == nil {
		t.Fatal("expected a missing config to be reported")
	}
}

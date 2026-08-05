package main

import (
	"reflect"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
)

func testTime() time.Time { return time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC) }

// The shape the live catalogue actually ships, measured 2026-08-04.
const sampleNodeName = "🇩🇪 | @WhiteDNS | DE1|36.8MB/s|DNSOK|GPT⁺-DE|CL-DE|SP-DE"

func TestCountryCodeFromNodeName(t *testing.T) {
	testCases := []struct {
		name string
		want string
	}{
		{sampleNodeName, "DE"},
		{"🇯🇵 | @WhiteDNS | JP12|5.1MB/s", "JP"},
		{"🇬🇧 | @WhiteDNS | GB1", "GB"},
		{"❓ | @WhiteDNS | XX1", ""},
		{"plain name with no flag", ""},
		{"", ""},
	}
	for _, testCase := range testCases {
		if got := countryCodeFromNodeName(testCase.name); got != testCase.want {
			t.Errorf("countryCodeFromNodeName(%q) = %q, want %q", testCase.name, got, testCase.want)
		}
	}
}

func TestNodeLabelDropsWhatEveryRowRepeats(t *testing.T) {
	got := nodeLabel(sampleNodeName)
	want := "DE1 · 36.8MB/s · DNSOK · GPT⁺-DE · CL-DE · SP-DE"
	if got != want {
		t.Fatalf("nodeLabel = %q, want %q", got, want)
	}
	if got := nodeLabel("🇯🇵"); got != "🇯🇵" {
		t.Fatalf("a name that is only a flag has nothing to drop, got %q", got)
	}
}

func nodesForTest() []model.WhiteVPNNode {
	return []model.WhiteVPNNode{
		{Name: "de-trojan", Type: "trojan", CountryCode: "DE"},
		{Name: "de-vless", Type: "vless", CountryCode: "DE"},
		{Name: "jp-vless", Type: "vless", CountryCode: "JP"},
		{Name: "unknown-ss", Type: "ss", CountryCode: ""},
	}
}

func TestPreferredNodeNames(t *testing.T) {
	testCases := []struct {
		name     string
		settings model.WhiteVPNSettings
		want     []string
	}{
		{
			name:     "automatic prefers nothing, so the catalogue's own order stands",
			settings: model.WhiteVPNSettings{},
			want:     nil,
		},
		{
			name:     "a country keeps only that country",
			settings: model.WhiteVPNSettings{CountryCode: "DE"},
			want:     []string{"de-trojan", "de-vless"},
		},
		{
			name:     "a type keeps only that type",
			settings: model.WhiteVPNSettings{Connection: model.ConnectionSelection{Types: []string{"vless"}}},
			want:     []string{"de-vless", "jp-vless"},
		},
		{
			name: "country and type together",
			settings: model.WhiteVPNSettings{
				CountryCode: "DE",
				Connection:  model.ConnectionSelection{Types: []string{"vless"}},
			},
			want: []string{"de-vless"},
		},
		{
			name: "an explicit pick is the only candidate, filters or no filters",
			settings: model.WhiteVPNSettings{
				CountryCode: "JP",
				Connection:  model.ConnectionSelection{Node: "de-trojan"},
			},
			want: []string{"de-trojan"},
		},
		{
			name:     "a pick that has left the catalogue matches nothing",
			settings: model.WhiteVPNSettings{Connection: model.ConnectionSelection{Node: "gone"}},
			want:     []string{},
		},
		{
			name:     "a country nothing is in matches nothing",
			settings: model.WhiteVPNSettings{CountryCode: "NZ"},
			want:     []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := preferredNodeNames(nodesForTest(), model.NormalizeWhiteVPNSettings(testCase.settings))
			if len(got) == 0 && len(testCase.want) == 0 {
				// Both empty; what matters is whether the caller may fall back,
				// and that is selectionIsNarrowed's job, tested below.
				return
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("preferredNodeNames = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

func TestSelectionIsNarrowedTellsEmptyApart(t *testing.T) {
	automatic := model.NormalizeWhiteVPNSettings(model.WhiteVPNSettings{})
	if selectionIsNarrowed(automatic) {
		t.Fatal("automatic asks for nothing in particular")
	}
	if len(preferredNodeNames(nodesForTest(), automatic)) != 0 {
		t.Fatal("automatic should prefer nothing, leaving the catalogue's order")
	}

	// The pair that matters: nothing preferred *and* something asked for means
	// the connect must fail rather than reach for the whole catalogue.
	narrowed := model.NormalizeWhiteVPNSettings(model.WhiteVPNSettings{CountryCode: "NZ"})
	if !selectionIsNarrowed(narrowed) {
		t.Fatal("a country filter is a narrowing")
	}
	if len(preferredNodeNames(nodesForTest(), narrowed)) != 0 {
		t.Fatal("no node is in NZ, so nothing may be preferred")
	}
}

func TestWhiteVPNNodesFromSubscriptionReadsShareLinks(t *testing.T) {
	// One trojan link, named the way the catalogue names them.
	subscription := "trojan://secret@example.com:443?sni=example.com&type=ws#" +
		"%F0%9F%87%A9%F0%9F%87%AA%20%7C%20%40WhiteDNS%20%7C%20DE1%7C36.8MB/s"

	nodes, err := whiteVPNNodesFromSubscription(subscription)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	node := nodes[0]
	if node.CountryCode != "DE" {
		t.Fatalf("expected the flag to give DE, got %q from %q", node.CountryCode, node.Name)
	}
	if node.Type != "trojan" {
		t.Fatalf("expected trojan, got %q", node.Type)
	}
	if node.Label != "DE1 · 36.8MB/s" {
		t.Fatalf("unexpected label %q", node.Label)
	}
}

func TestRecordConnectedNodeReadsTheFlagAndDropsTheOldMeasurement(t *testing.T) {
	app := &App{state: model.DefaultAppState(), proxyCountryCache: map[string]proxyCountryCacheEntry{}}
	app.state.Runtime.Status = model.RuntimeConnected
	// A measurement belonging to the node about to be left.
	app.state.Runtime.PublicProxyIP = "203.0.113.7"
	app.state.Runtime.ExitCountryCode = "JP"
	app.state.Runtime.ExitChecked = true
	app.proxyCountryCache["socks://127.0.0.1:2080"] = proxyCountryCacheEntry{}
	events := []string{}
	app.emitHook = func(name string, _ any) { events = append(events, name) }

	app.recordConnectedNode(sampleNodeName)
	runtimeState := app.GetAppState().Runtime

	if runtimeState.NodeName != sampleNodeName {
		t.Fatalf("expected the node to be recorded, got %q", runtimeState.NodeName)
	}
	if runtimeState.NodeCountryCode != "DE" {
		t.Fatalf("expected the flag to give DE, got %q", runtimeState.NodeCountryCode)
	}
	if runtimeState.PublicProxyIP != "" || runtimeState.ExitCountryCode != "" || runtimeState.ExitChecked {
		t.Fatalf("the previous node's measurement must not carry over, got %#v", runtimeState)
	}
	if len(app.proxyCountryCache) != 0 {
		// The cache is keyed by the local proxy address, which does not change
		// when the node behind it does.
		t.Fatal("expected the country cache to be cleared with the node")
	}
	if len(events) != 1 {
		t.Fatalf("expected the interface to be told once, got %#v", events)
	}
}

func TestDisconnectingForgetsWhereTrafficLeftFrom(t *testing.T) {
	app := &App{state: model.DefaultAppState(), proxyCountryCache: map[string]proxyCountryCacheEntry{}}
	app.state.Runtime.Status = model.RuntimeConnected
	app.state.Runtime.NodeName = sampleNodeName
	app.state.Runtime.NodeCountryCode = "DE"
	app.state.Runtime.ExitCountryCode = "DE"
	app.state.Runtime.ExitChecked = true

	app.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")

	runtimeState := app.GetAppState().Runtime
	if runtimeState.NodeName != "" || runtimeState.NodeCountryCode != "" || runtimeState.ExitCountryCode != "" || runtimeState.ExitChecked {
		t.Fatalf("expected the connection's country to be forgotten with it, got %#v", runtimeState)
	}
}

func TestStoreWhiteVPNNodesKeepsMeasurements(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.storeWhiteVPNNodes([]model.WhiteVPNNode{{Name: "a"}, {Name: "b"}}, testTime())
	app.applyWhiteVPNNodeDelays(map[string]nodeDelay{"a": {delayMs: 120, ok: true}})

	// A refresh that still holds the node must not throw its measurement away.
	list := app.storeWhiteVPNNodes([]model.WhiteVPNNode{{Name: "a"}, {Name: "c"}}, testTime())
	if len(list.Nodes) != 2 {
		t.Fatalf("expected the refreshed catalogue, got %#v", list.Nodes)
	}
	if !list.Nodes[0].DelayOK || list.Nodes[0].DelayMs != 120 {
		t.Fatalf("expected the measurement to survive a refresh, got %#v", list.Nodes[0])
	}
	if list.Nodes[1].DelayOK {
		t.Fatalf("a node never measured must not inherit one, got %#v", list.Nodes[1])
	}
}

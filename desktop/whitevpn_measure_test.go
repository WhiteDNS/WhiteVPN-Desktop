package main

import (
	"context"
	"testing"

	"whitevpn-desktop/internal/model"
)

// A test that ran and failed is not a test that never ran. A user reported
// nodes whose tests "did not happen"; they had happened and failed, and the two
// looked identical because only the OK flag distinguished them.
func TestReachabilityRecordsFailureAsTested(t *testing.T) {
	app := &App{state: model.DefaultAppState(), proxyCountryCache: map[string]proxyCountryCacheEntry{}}
	app.storeWhiteVPNNodes(whiteDNSVPNSubscriptionID, []model.WhiteVPNNode{
		{Name: "no-address", Server: "", Port: 0},
	}, testTime())

	request := model.NormalizeNodeTestRequest(model.NodeTestRequest{Nodes: []string{"no-address"}, Reachability: true})
	app.measureReachability(context.Background(), whiteDNSVPNSubscriptionID, app.whiteVPNNodesSnapshot(whiteDNSVPNSubscriptionID), request)

	node := app.whiteVPNNodesSnapshot(whiteDNSVPNSubscriptionID)[0]
	if !node.ReachTested {
		t.Fatal("a node with nothing to dial was left looking untested, so its row would never resolve")
	}
	if node.ReachOK {
		t.Fatal("a node with no address cannot be reachable")
	}
}

// Measurements survive a catalogue refresh, including the fact that they were
// taken at all.
func TestRefreshKeepsWhetherATestWasRun(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.storeWhiteVPNNodes(whiteDNSVPNSubscriptionID, []model.WhiteVPNNode{{Name: "a"}}, testTime())
	app.recordNodeMeasurement(whiteDNSVPNSubscriptionID, "a", func(node *model.WhiteVPNNode) {
		node.ReachTested, node.ReachOK = true, false
		node.DelayTested, node.DelayOK, node.DelayMs = true, true, 120
	})

	list := app.storeWhiteVPNNodes(whiteDNSVPNSubscriptionID, []model.WhiteVPNNode{{Name: "a"}}, testTime())
	node := list.Nodes[0]
	if !node.ReachTested || node.ReachOK {
		t.Fatalf("a failed reachability test should survive as failed, got %#v", node)
	}
	if !node.DelayTested || !node.DelayOK || node.DelayMs != 120 {
		t.Fatalf("a delay measurement should survive intact, got %#v", node)
	}
}

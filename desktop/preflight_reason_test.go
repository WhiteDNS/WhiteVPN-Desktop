package main

import (
	"context"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

// "connection preflight failed" alone sent a user hunting; the app made the
// reason, so it shows it — with any URL in it scrubbed.
func TestARefusedConnectionKeepsItsReason(t *testing.T) {
	a := newSnapshotTestApp(t)
	a.state.WhiteVPN.Chain = model.ChainSettings{
		Entry: model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: "gone", Node: "A"},
		Exit:  model.ChainHop{Mode: model.ChainHopFixed, SubscriptionID: "gone", Node: "B"},
	}
	b := &mihomoBackend{app: a}
	_, err := b.Prepare(context.Background(), a.managedRequest())
	if err == nil {
		t.Fatal("a chain over a list that does not exist was prepared")
	}
	reason := a.lastPreflightReason()
	if reason == "" || reason != model.PublicText(err.Error()) {
		t.Fatalf("reason = %q, want the scrubbed error %q", reason, err.Error())
	}
	if strings.Contains(reason, "https://") {
		t.Fatalf("reason carries a URL: %q", reason)
	}
}

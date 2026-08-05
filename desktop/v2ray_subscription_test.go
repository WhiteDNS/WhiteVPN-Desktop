package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

// addTestSubscription puts a subscription into the state as a save would, but
// without the HTTPS requirement: these tests exercise refreshing, and the local
// test server speaks plain HTTP.
func addTestSubscription(t *testing.T, app *App, name string, url string) string {
	t.Helper()
	app.mu.Lock()
	defer app.mu.Unlock()
	id := uniqueV2RaySubscriptionID(app.state.V2RaySubscriptions)
	app.state.V2RaySubscriptions = append(app.state.V2RaySubscriptions, model.V2RaySubscription{
		ID: id, Name: name, URL: url,
	})
	if _, err := app.saveLocked(); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRefreshV2RaySubscriptionImportsAndReplacesManagedProfiles(t *testing.T) {
	body := testV2RaySubscriptionLink("one")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	app := testV2RaySubscriptionApp(t)

	subscriptionID := addTestSubscription(t, app, "Sub", server.URL)
	first, err := app.RefreshV2RaySubscription(subscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if !first.OK || first.Imported != 1 || first.Removed != 0 {
		t.Fatalf("unexpected first refresh: %#v", first)
	}
	if len(first.State.V2RayProfiles) != 1 || first.State.V2RayProfiles[0].SubscriptionID != subscriptionID {
		t.Fatalf("expected one managed profile, got %#v", first.State.V2RayProfiles)
	}

	manual := duplicateTestV2RayProfile("manual", "Manual")
	manual.Server = "manual.example.com"
	if _, err := app.SaveV2RayProfile(manual); err != nil {
		t.Fatal(err)
	}
	body = testV2RaySubscriptionLink("two")

	second, err := app.RefreshV2RaySubscription(subscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if !second.OK || second.Imported != 1 || second.Removed != 1 {
		t.Fatalf("unexpected second refresh: %#v", second)
	}
	if !containsV2RayProfile(second.State.V2RayProfiles, "manual") {
		t.Fatalf("manual profile should be preserved: %#v", second.State.V2RayProfiles)
	}
	if findV2RayProfileServer(second.State.V2RayProfiles, "one.example.com") {
		t.Fatalf("old subscription profile should be replaced: %#v", second.State.V2RayProfiles)
	}
	if !findV2RayProfileServer(second.State.V2RayProfiles, "two.example.com") {
		t.Fatalf("new subscription profile missing: %#v", second.State.V2RayProfiles)
	}
}

func TestRefreshV2RaySubscriptionFailurePreservesExistingProfiles(t *testing.T) {
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "failed", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(testV2RaySubscriptionLink("stable")))
	}))
	defer server.Close()
	app := testV2RaySubscriptionApp(t)

	subscriptionID := addTestSubscription(t, app, "Sub", server.URL)
	if _, err := app.RefreshV2RaySubscription(subscriptionID); err != nil {
		t.Fatal(err)
	}
	fail = true

	result, err := app.RefreshV2RaySubscription(subscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK || !strings.Contains(result.Message, "HTTP 500") {
		t.Fatalf("expected failed refresh result, got %#v", result)
	}
	if len(result.State.V2RayProfiles) != 1 || result.State.V2RayProfiles[0].Server != "stable.example.com" {
		t.Fatalf("failed refresh should preserve old profiles: %#v", result.State.V2RayProfiles)
	}
	if result.Subscription.LastError == "" {
		t.Fatalf("expected subscription last error to be recorded: %#v", result.Subscription)
	}
}

func TestDeleteV2RaySubscriptionRemovesManagedProfiles(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testV2RaySubscriptionLink("delete")))
	}))
	defer server.Close()

	subscriptionID := addTestSubscription(t, app, "Sub", server.URL)
	if _, err := app.RefreshV2RaySubscription(subscriptionID); err != nil {
		t.Fatal(err)
	}
	manual := duplicateTestV2RayProfile("manual-delete", "Manual")
	manual.Server = "manual-delete.example.com"
	if _, err := app.SaveV2RayProfile(manual); err != nil {
		t.Fatal(err)
	}

	next, err := app.DeleteV2RaySubscription(subscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.V2RaySubscriptions) != 0 || len(next.V2RayProfiles) != 1 {
		t.Fatalf("expected subscription and managed profiles to be deleted, got %#v / %#v", next.V2RaySubscriptions, next.V2RayProfiles)
	}
	if next.V2RayProfiles[0].ID != manual.ID || next.V2RayProfiles[0].SubscriptionID != "" {
		t.Fatalf("expected manual profile to be preserved without subscription ownership, got %#v", next.V2RayProfiles)
	}
}

func TestSaveV2RaySubscriptionRejectsNonHTTPURL(t *testing.T) {
	app := testV2RaySubscriptionApp(t)

	if _, err := app.SaveV2RaySubscription(model.V2RaySubscription{Name: "Bad", URL: "file:///tmp/sub.txt"}); err == nil {
		t.Fatal("expected non-http subscription URL to be rejected")
	}
}

func TestRefreshV2RaySubscriptionRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", v2raySubscriptionMaxBytes+1)))
	}))
	defer server.Close()
	app := testV2RaySubscriptionApp(t)

	state, err := app.SaveV2RaySubscription(model.V2RaySubscription{Name: "Big", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.RefreshV2RaySubscription(state.V2RaySubscriptions[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK || !strings.Contains(result.Message, "too large") {
		t.Fatalf("expected oversized response failure, got %#v", result)
	}
}

func testV2RaySubscriptionApp(t *testing.T) *App {
	t.Helper()
	return &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: model.DefaultAppState(),
	}
}

func testV2RaySubscriptionLink(name string) string {
	return "vless://11111111-1111-1111-1111-111111111111@" + name + ".example.com:443?security=tls&type=tcp#" + name
}

func findV2RayProfileServer(items []model.V2RayProfile, server string) bool {
	for _, item := range items {
		if item.Server == server {
			return true
		}
	}
	return false
}

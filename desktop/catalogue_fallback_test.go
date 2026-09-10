package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	privateTestNode = "vless://11111111-1111-1111-1111-111111111111@private.example.com:443?security=tls&type=tcp#Private"
	publicTestNode  = "vless://22222222-2222-2222-2222-222222222222@public.example.com:443?security=tls&type=tcp#Public"
)

// catalogueFallbackApp wires both catalogues at addresses the test controls.
// privateBody empty means the private list cannot be fetched.
func catalogueFallbackApp(t *testing.T, privateBody string) (*App, *[]string) {
	t.Helper()

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(encryptWhiteDNSVPNTestPayload(t, publicTestNode)))
	}))
	t.Cleanup(public.Close)

	privateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if privateBody == "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(privateBody))
	}))
	t.Cleanup(privateServer.Close)

	restoreURL, restoreKey, restorePrivate := whiteDNSVPNSubscriptionURL, whiteDNSVPNSubscriptionKey, whiteVPNPrivateSubscriptionURL
	whiteDNSVPNSubscriptionURL = public.URL
	whiteDNSVPNSubscriptionKey = testCatalogueKey
	whiteVPNPrivateSubscriptionURL = privateServer.URL
	t.Cleanup(func() {
		whiteDNSVPNSubscriptionURL, whiteDNSVPNSubscriptionKey, whiteVPNPrivateSubscriptionURL = restoreURL, restoreKey, restorePrivate
	})

	dir := t.TempDir()
	app := &App{
		store:     profiles.NewStore(filepath.Join(dir, "state.json")),
		configDir: dir,
		state:     model.DefaultAppState(),
	}
	notices := &[]string{}
	app.emitHook = func(name string, payload any) {
		if name == "runtime:notice" {
			if text, ok := payload.(string); ok {
				*notices = append(*notices, text)
			}
		}
	}
	app.mu.Lock()
	app.ensureBuiltInCataloguesLocked()
	_, _ = app.saveLocked()
	app.mu.Unlock()
	return app, notices
}

// Somebody whose private list cannot be fetched is somebody with no working
// VPN, on a machine where that is often the point. The public one is there.
func TestAnUnreachablePrivateListFallsBackToThePublicOne(t *testing.T) {
	app, notices := catalogueFallbackApp(t, "")

	body, usedID, err := app.subscriptionBodyWithFallback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usedID != whiteDNSVPNSubscriptionID {
		t.Fatalf("expected the public catalogue to be used, got %q", usedID)
	}
	if !strings.Contains(body, "public.example.com") {
		t.Fatalf("the public catalogue's body was not returned: %q", body)
	}

	// Told, not switched silently.
	if len(*notices) != 1 {
		t.Fatalf("expected exactly one notice, got %#v", *notices)
	}
	for _, word := range []string{"private", "public"} {
		if !strings.Contains(strings.ToLower((*notices)[0]), word) {
			t.Errorf("the notice does not mention %q: %q", word, (*notices)[0])
		}
	}

	// The choice is the user's and stays theirs, so the next attempt tries the
	// private list again rather than settling on the fallback for ever.
	if got := app.selectedSubscriptionID(); got != whiteVPNPrivateSubscriptionID {
		t.Fatalf("the fallback rewrote the stored choice to %q", got)
	}
}

// No notice and no detour when the private list is working.
func TestAWorkingPrivateListIsUsedAndSaysNothing(t *testing.T) {
	app, notices := catalogueFallbackApp(t, privateTestNode)

	body, usedID, err := app.subscriptionBodyWithFallback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usedID != whiteVPNPrivateSubscriptionID || !strings.Contains(body, "private.example.com") {
		t.Fatalf("used %q with body %q", usedID, body)
	}
	if len(*notices) != 0 {
		t.Fatalf("a working connection should say nothing, got %#v", *notices)
	}
}

// Public is not a list anyone is dropped off, so there is no fallback the other
// way. Its failure is reported as its own.
func TestThePublicListDoesNotFallBackToThePrivateOne(t *testing.T) {
	app, notices := catalogueFallbackApp(t, privateTestNode)
	whiteDNSVPNSubscriptionURL = "http://127.0.0.1:1/gone"
	if _, err := app.SelectSubscription(whiteDNSVPNSubscriptionID); err != nil {
		t.Fatal(err)
	}

	if _, _, err := app.subscriptionBodyWithFallback(context.Background()); err == nil {
		t.Fatal("expected the public catalogue's failure to be reported")
	}
	if len(*notices) != 0 {
		t.Fatalf("expected no fallback notice, got %#v", *notices)
	}
}

// When neither can be fetched, the error is the private one's — the list the
// user asked for. The fallback failing as well says nothing they can act on.
func TestWhenNeitherIsReachableThePrivateFailureIsReported(t *testing.T) {
	app, notices := catalogueFallbackApp(t, "")
	whiteDNSVPNSubscriptionURL = "http://127.0.0.1:1/gone"

	_, usedID, err := app.subscriptionBodyWithFallback(context.Background())
	if err == nil {
		t.Fatal("expected an error when neither list can be fetched")
	}
	if usedID != whiteVPNPrivateSubscriptionID {
		t.Fatalf("the failure should be attributed to the chosen list, got %q", usedID)
	}
	if len(*notices) != 0 {
		t.Fatalf("a fallback that did not work must not claim it did: %#v", *notices)
	}
}

// A build with no public catalogue has nothing to fall back to, and must not
// pretend otherwise.
func TestNoFallbackWhenThisBuildHasNoPublicCatalogue(t *testing.T) {
	app, notices := catalogueFallbackApp(t, "")
	whiteDNSVPNSubscriptionURL = ""
	whiteDNSVPNSubscriptionKey = ""

	if _, _, err := app.subscriptionBodyWithFallback(context.Background()); err == nil {
		t.Fatal("expected the private failure to stand")
	}
	if len(*notices) != 0 {
		t.Fatalf("expected no notice, got %#v", *notices)
	}
}

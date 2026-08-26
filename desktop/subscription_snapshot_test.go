package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

// A provider that cannot be reached is the ordinary case for this app, not the
// exceptional one. Before this, it meant a machine holding a good node list from
// ten minutes ago could not connect at all.
func TestAFailedFetchFallsBackToTheLastBodyThatWorked(t *testing.T) {
	app := newSnapshotTestApp(t)

	app.fetchSubscriptionHook = func(context.Context, string) (string, error) {
		return subscriptionLinks, nil
	}
	body, origin, err := app.resolveSubscriptionBody(context.Background(), "provider")
	if err != nil {
		t.Fatal(err)
	}
	if origin != originRefreshed || body != subscriptionLinks {
		t.Fatalf("a successful fetch should be reported as fetched: got origin %q", origin)
	}

	app.fetchSubscriptionHook = func(context.Context, string) (string, error) {
		return "", errors.New("dial tcp: i/o timeout")
	}
	body, origin, err = app.resolveSubscriptionBody(context.Background(), "provider")
	if err != nil {
		t.Fatalf("the stored body should have answered this: %v", err)
	}
	if origin != originLastKnownGood {
		t.Fatalf("content served from a failed refresh must not be reported as fetched: got %q", origin)
	}
	if body != subscriptionLinks {
		t.Fatal("the body that came back is not the one that was stored")
	}
}

// The failure mode that loses the only good copy: a provider that answers, but
// not with a subscription. A captive portal's login page is still a 200.
func TestAnUnparseableBodyNeverReplacesAGoodOne(t *testing.T) {
	app := newSnapshotTestApp(t)

	app.fetchSubscriptionHook = func(context.Context, string) (string, error) {
		return subscriptionLinks, nil
	}
	if _, _, err := app.resolveSubscriptionBody(context.Background(), "provider"); err != nil {
		t.Fatal(err)
	}

	app.fetchSubscriptionHook = func(context.Context, string) (string, error) {
		return "<html><body>Please sign in to this network</body></html>", nil
	}
	body, origin, err := app.resolveSubscriptionBody(context.Background(), "provider")
	if err != nil {
		t.Fatalf("the previous body was still good and should have been used: %v", err)
	}
	if origin != originLastKnownGood || body != subscriptionLinks {
		t.Fatal("a login page replaced a working subscription")
	}

	stored, ok := app.lastKnownGoodSubscription("provider")
	if !ok || stored.Body != subscriptionLinks {
		t.Fatal("the stored copy was overwritten by content that does not parse")
	}
}

// Nothing is stored until it has been shown to hold servers, and a body that
// holds none is not a subscription with no servers today — it is a wrong file.
func TestABodyWithNoServersIsNotStored(t *testing.T) {
	app := newSnapshotTestApp(t)
	if err := app.storeSubscriptionSnapshot("provider", "proxies: []\n", 0); err == nil {
		t.Fatal("expected an empty body to be refused")
	}
	if _, ok := app.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("nothing should have been written")
	}
}

// A stored file that no longer parses is thrown away rather than served. Keeping
// it would answer every failed fetch with something known to be useless.
func TestACorruptStoredBodyIsDiscardedRatherThanServed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		written string
	}{
		{"the file is not readable at all", "{ this is not json"},
		{"the file is readable but holds no subscription", `{"subscriptionId":"provider","body":"<html>login</html>","nodeCount":7}`},
		{"the file belongs to another subscription", `{"subscriptionId":"somebody-else","body":"` + strings.ReplaceAll(subscriptionLinks, "\n", `\n`) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newSnapshotTestApp(t)
			if err := os.MkdirAll(app.subscriptionSnapshotDir(), 0o755); err != nil {
				t.Fatal(err)
			}
			path := app.subscriptionSnapshotPath("provider")
			if err := os.WriteFile(path, []byte(tc.written), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, ok := app.lastKnownGoodSubscription("provider"); ok {
				t.Fatal("a body that cannot be used was served anyway")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("expected the unusable file to be removed so it is fetched again")
			}
		})
	}
}

// The manual list is built from the user's own configs every time it is asked
// for. It cannot fail to be available, so a second copy could only go stale.
func TestTheManualListIsNeverStored(t *testing.T) {
	app := newSnapshotTestApp(t)
	app.fetchSubscriptionHook = func(context.Context, string) (string, error) {
		return subscriptionLinks, nil
	}
	if _, _, err := app.resolveSubscriptionBody(context.Background(), model.ManualServerSourceID); err != nil {
		t.Fatal(err)
	}
	if _, ok := app.lastKnownGoodSubscription(model.ManualServerSourceID); ok {
		t.Fatal("the manual list should not have been written to disk")
	}
}

// With nothing stored, a failed fetch still fails. The fallback is a second
// answer, not a way of never reporting the first.
func TestAFailedFetchWithNothingStoredStillFails(t *testing.T) {
	app := newSnapshotTestApp(t)
	app.fetchSubscriptionHook = func(context.Context, string) (string, error) {
		return "", errors.New("dial tcp: i/o timeout")
	}
	if _, _, err := app.resolveSubscriptionBody(context.Background(), "provider"); err == nil {
		t.Fatal("expected the fetch failure to be reported when there is nothing to fall back to")
	}
}

// A subscription the user removed must not leave its servers behind.
func TestDeletingASubscriptionRemovesItsStoredBody(t *testing.T) {
	app := newSnapshotTestApp(t)
	if err := app.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	app.forgetSubscriptionSnapshot("provider")
	if _, ok := app.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("the stored body outlived the subscription it belonged to")
	}
}

func newSnapshotTestApp(t *testing.T) *App {
	t.Helper()
	return &App{state: model.DefaultAppState(), configDir: t.TempDir()}
}

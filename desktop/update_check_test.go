package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
)

// A string comparison puts 1.0.10 below 1.0.9 and stops offering updates at
// exactly the point a project has shipped ten patches.
func TestNewerVersionComparesNumbersNotText(t *testing.T) {
	for _, testCase := range []struct {
		candidate, current string
		want               bool
	}{
		{"1.0.4", "1.0.3", true},
		{"1.0.10", "1.0.9", true},
		{"1.1.0", "1.0.9", true},
		{"2.0.0", "1.9.9", true},
		{"1.0.3", "1.0.3", false},
		{"1.0.2", "1.0.3", false},
		{"1.0.9", "1.0.10", false},
		// Shorter is not older when the missing parts are zero.
		{"1.1", "1.1.0", false},
		{"1.1.1", "1.1", true},
		// A leading v is how the tags are written.
		{"v1.0.4", "1.0.3", true},
		// A prerelease compares on its numbers.
		{"1.0.4-beta1", "1.0.3", true},
	} {
		if got := newerVersion(testCase.candidate, testCase.current); got != testCase.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", testCase.candidate, testCase.current, got, testCase.want)
		}
	}
}

// Anything unparseable must sort as older, so a version this app cannot
// understand never prompts an upgrade to it.
func TestNewerVersionRefusesWhatItCannotRead(t *testing.T) {
	for _, testCase := range [][2]string{
		{"", "1.0.3"},
		{"latest", "1.0.3"},
		{"1.0.x", "1.0.3"},
		{"1.0.4", "dev"},
		{"1.0.4", ""},
	} {
		if newerVersion(testCase[0], testCase[1]) {
			t.Errorf("newerVersion(%q, %q) should be false", testCase[0], testCase[1])
		}
	}
}

// A development build has no release to compare against, and offering to
// "update" one would be nonsense. It also must not spend a request finding that
// out.
func TestCheckForUpdateLeavesDevelopmentBuildsAlone(t *testing.T) {
	restore := appVersion
	appVersion = "dev"
	defer func() { appVersion = restore }()

	app := &App{}
	status, err := app.CheckForUpdate(true)
	if err != nil {
		t.Fatal(err)
	}
	if status.Available {
		t.Fatalf("a dev build should never be offered an update: %#v", status)
	}
	if status.Current != "dev" {
		t.Fatalf("expected the running version to be reported, got %q", status.Current)
	}
}

func TestRequestLatestReleaseReadsAPublishedRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.4","html_url":"https://example.com/v1.0.4","body":"notes","draft":false,"prerelease":false}`))
	}))
	defer server.Close()

	release, err := requestLatestReleaseFrom(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if release.TagName != "v1.0.4" || release.HTMLURL != "https://example.com/v1.0.4" {
		t.Fatalf("unexpected release: %#v", release)
	}
}

// A draft or a prerelease is not something to send people to.
func TestRequestLatestReleaseSkipsUnpublished(t *testing.T) {
	for _, body := range []string{
		`{"tag_name":"v1.0.5","draft":true}`,
		`{"tag_name":"v1.0.5","prerelease":true}`,
		`{"tag_name":""}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		if _, err := requestLatestReleaseFrom(context.Background(), server.Client(), server.URL); err == nil {
			t.Errorf("%s should have been refused", body)
		}
		server.Close()
	}
}

func TestRequestLatestReleaseReportsARefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	if _, err := requestLatestReleaseFrom(context.Background(), server.Client(), server.URL); err == nil {
		t.Fatal("expected a rate-limited or refused response to be an error")
	}
}

// Not reaching GitHub is ordinary where this app is used. It must not surface as
// a failed call, and it must not claim an update is available.
func TestCheckForUpdateSurvivesAnUnreachableGitHub(t *testing.T) {
	restore := appVersion
	appVersion = "1.0.3"
	defer func() { appVersion = restore }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	server.Close() // nothing is listening now

	app := &App{}
	status, err := app.checkForUpdateAt(server.URL, true)
	if err != nil {
		t.Fatalf("an unreachable release list should not fail the call: %v", err)
	}
	if status.Available {
		t.Fatal("a failed check must not offer an update")
	}
	if status.Error == "" {
		t.Fatal("the failure should be reported so the interface can say the check did not run")
	}
}

func TestCheckForUpdateCachesItsAnswer(t *testing.T) {
	restore := appVersion
	appVersion = "1.0.3"
	defer func() { appVersion = restore }()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.4","html_url":"https://example.com","body":"","draft":false,"prerelease":false}`))
	}))
	defer server.Close()

	app := &App{}
	first, err := app.checkForUpdateAt(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Available || first.Latest != "1.0.4" {
		t.Fatalf("expected 1.0.4 to be offered: %#v", first)
	}

	// Sixty requests an hour, unauthenticated, so asking again must not ask
	// GitHub again.
	if _, err := app.checkForUpdateAt(server.URL, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected the answer to be cached, made %d requests", calls)
	}

	// Unless the user asks, which is the point of force.
	if _, err := app.checkForUpdateAt(server.URL, true); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("a forced check should have gone out, made %d requests", calls)
	}
}

func TestUpdateCacheExpires(t *testing.T) {
	cache := &updateCheckCache{}
	cache.put(model.UpdateStatus{Latest: "1.0.4", Available: true})
	if _, ok := cache.get(); !ok {
		t.Fatal("a fresh answer should be served from the cache")
	}
	cache.checkedAt = time.Now().Add(-updateCheckInterval - time.Minute)
	if _, ok := cache.get(); ok {
		t.Fatal("a stale answer should not be served")
	}
}

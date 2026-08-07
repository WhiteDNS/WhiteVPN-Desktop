package main

// Telling a user a newer version exists.
//
// This checks and reports. It does not download anything and does not replace
// anything, and that is deliberate rather than unfinished: the app runs as
// Administrator and nothing it ships is code-signed, so an updater that fetched
// a binary and ran it would hand whoever could interfere with that download a
// machine with full privileges. Doing that safely needs signed artifacts and
// verification before the swap, which is its own piece of work.
//
// What is left is still most of the value. The problem is not that people cannot
// replace a file — it is that they do not know there is anything to replace. The
// users still on an old version are the ones who are not in the Telegram channel,
// which is exactly who an in-app notice reaches.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
)

const (
	// The releases API, unauthenticated. Sixty requests an hour per address,
	// which is why the result is cached rather than fetched whenever something
	// asks.
	latestReleaseURL = "https://api.github.com/repos/WhiteDNS/WhiteVPN-Desktop/releases/latest"

	updateCheckInterval = 6 * time.Hour
	updateCheckTimeout  = 12 * time.Second
)

type updateCheckCache struct {
	mu        sync.Mutex
	result    model.UpdateStatus
	checkedAt time.Time
}

// CheckForUpdate reports whether a newer release exists.
//
// force skips the cache, for the case where a user asks rather than the app
// asking on its own.
func (a *App) CheckForUpdate(force bool) (model.UpdateStatus, error) {
	return a.checkForUpdateAt(latestReleaseURL, force)
}

// checkForUpdateAt is CheckForUpdate with the address as an argument, so the
// behaviour around it — the cache, a dev build, an unreachable list — can be
// tested without reaching GitHub.
func (a *App) checkForUpdateAt(releaseURL string, force bool) (model.UpdateStatus, error) {
	if !force {
		if cached, ok := a.updates.get(); ok {
			return cached, nil
		}
	}

	current := strings.TrimSpace(appVersion)
	if current == "" || current == "dev" {
		// A development build has no release to compare against, and offering to
		// "update" one to the version it was built after would be nonsense.
		status := model.UpdateStatus{Current: current, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		a.updates.put(status)
		return status, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	defer cancel()

	release, err := a.fetchLatestRelease(ctx, releaseURL)
	if err != nil {
		// Not being able to reach GitHub is ordinary — it is blocked in the
		// places this app is used — so it is reported as a failed check rather
		// than as an error worth interrupting anyone over.
		status := model.UpdateStatus{
			Current:   current,
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
			Error:     err.Error(),
		}
		a.updates.put(status)
		return status, nil
	}

	latest := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	status := model.UpdateStatus{
		Current:   current,
		Latest:    latest,
		URL:       strings.TrimSpace(release.HTMLURL),
		Notes:     strings.TrimSpace(release.Body),
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Available: newerVersion(latest, current),
	}
	a.updates.put(status)
	return status, nil
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// fetchLatestRelease asks GitHub, through the tunnel when there is one.
//
// Through the tunnel first because GitHub is often unreachable from the networks
// this app exists to get around, and a user who is connected has a working path
// to it. Falling back to a direct request covers the other case — checking
// before connecting, on a network where GitHub is fine.
func (a *App) fetchLatestRelease(ctx context.Context, releaseURL string) (githubRelease, error) {
	var lastErr error
	for _, client := range a.updateCheckClients() {
		release, err := requestLatestReleaseFrom(ctx, client, releaseURL)
		if err == nil {
			return release, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no way to reach the release list")
	}
	return githubRelease{}, lastErr
}

func (a *App) updateCheckClients() []*http.Client {
	clients := make([]*http.Client, 0, 2)
	if proxied, err := a.proxyHTTPClient(); err == nil && proxied != nil {
		clients = append(clients, proxied)
	}
	return append(clients, &http.Client{Timeout: updateCheckTimeout})
}

// proxyHTTPClient is a client that goes through the running connection, or nil
// when nothing is running.
func (a *App) proxyHTTPClient() (*http.Client, error) {
	current := a.mihomo.current()
	if current == nil {
		return nil, nil
	}
	return httpClientThroughProxy(runtimeProxyConfig{
		Protocol: "http",
		Address:  fmt.Sprintf("127.0.0.1:%d", current.MixedPort()),
	})
}

func requestLatestReleaseFrom(ctx context.Context, client *http.Client, releaseURL string) (githubRelease, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseURL, nil)
	if err != nil {
		return githubRelease{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "WhiteVPN-Desktop")

	response, err := client.Do(request)
	if err != nil {
		return githubRelease{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("the release list answered %d", response.StatusCode)
	}

	// Bounded: this is a small JSON document and the body is whatever the other
	// end decides to send.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return githubRelease{}, err
	}
	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return githubRelease{}, fmt.Errorf("the release list could not be read: %w", err)
	}
	if release.Draft || release.Prerelease {
		return githubRelease{}, fmt.Errorf("the latest release is not a published one")
	}
	if strings.TrimSpace(release.TagName) == "" {
		return githubRelease{}, fmt.Errorf("the release list named no version")
	}
	return release, nil
}

// newerVersion compares two dotted versions numerically.
//
// Not a string comparison, which would put 1.0.10 below 1.0.9 and stop offering
// updates at exactly the point a project has shipped ten patches. Anything that
// does not parse sorts as older, so a version this app cannot understand never
// prompts an upgrade to it.
func newerVersion(candidate, current string) bool {
	left, leftOK := versionParts(candidate)
	right, rightOK := versionParts(current)
	if !leftOK || !rightOK {
		return false
	}
	for i := 0; i < len(left) || i < len(right); i++ {
		a, b := 0, 0
		if i < len(left) {
			a = left[i]
		}
		if i < len(right) {
			b = right[i]
		}
		if a != b {
			return a > b
		}
	}
	return false
}

func versionParts(value string) ([]int, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	// A suffix like 1.0.0-beta2 compares on its numbers; the suffix itself says
	// nothing this needs.
	if cut := strings.IndexAny(value, "-+"); cut >= 0 {
		value = value[:cut]
	}
	if value == "" {
		return nil, false
	}
	fields := strings.Split(value, ".")
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		number, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || number < 0 {
			return nil, false
		}
		parts = append(parts, number)
	}
	return parts, true
}

func (c *updateCheckCache) get() (model.UpdateStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checkedAt.IsZero() || time.Since(c.checkedAt) >= updateCheckInterval {
		return model.UpdateStatus{}, false
	}
	return c.result, true
}

func (c *updateCheckCache) put(status model.UpdateStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.result = status
	c.checkedAt = time.Now()
}

// Package session connects: it turns a subscription and a set of settings into a
// running engine, and decides when that engine may be called connected.
package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// The health check, matching WhiteVPN for Android.
//
// Its existence is the point. The engine reports success from startListener even
// when it has failed to create a tunnel, so nothing it says about itself can be
// the basis for telling a user they are connected. A real request that comes
// back through the proxy can.
var healthURLs = []string{
	"https://valid-isrgrootx1.letsencrypt.org/",
	"https://connectivitycheck.gstatic.com/generate_204",
	"https://cloudflare.com/cdn-cgi/trace",
}

const (
	healthBudget       = 12 * time.Second
	healthPollInterval = 500 * time.Millisecond
	healthProbeTimeout = 3 * time.Second
)

// probeStatus makes one request through the local proxy and returns the status
// code. Three URLs are tried because any single one of them can be blocked or
// simply having a bad day, and treating that as "the tunnel is broken" would
// fail a connection that works.
func probeStatus(ctx context.Context, proxyPort int) int {
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	if err != nil {
		return -1
	}
	client := &http.Client{
		Timeout:   healthProbeTimeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		// A redirect is a perfectly good sign that traffic is flowing, and
		// following it only costs time.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, target := range healthURLs {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		_ = response.Body.Close()
		if healthy(response.StatusCode) {
			return response.StatusCode
		}
	}
	return -1
}

func healthy(code int) bool { return code == 204 || (code >= 200 && code < 400) }

// waitForHealthy polls until the proxy carries a real request or the budget runs
// out. The engine needs a moment after startListener before it will serve
// anything, so the first attempt failing means very little.
func waitForHealthy(ctx context.Context, probe func(context.Context) int) (int, error) {
	deadline, cancel := context.WithTimeout(ctx, healthBudget)
	defer cancel()

	for {
		if code := probe(deadline); healthy(code) {
			return code, nil
		}
		select {
		case <-deadline.Done():
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 0, fmt.Errorf("no request completed through the proxy within %s", healthBudget)
		case <-time.After(healthPollInterval):
		}
	}
}

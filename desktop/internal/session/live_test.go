package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

// This is the only test that answers the question the whole package exists for:
// given the real subscription and the real engine, does traffic actually leave
// through a server rather than the machine's own connection?
//
// It needs the engine built and the catalogue's credentials, and skips without
// them, so it never makes CI depend on either. It stays in proxy mode: a tunnel
// would need Administrator and would reroute the machine, and neither is
// necessary to prove that the pieces fit together.
//
//	WHITEVPN_CATALOGUE_URL=... WHITEVPN_CATALOGUE_KEY=... go test ./internal/session -run Live -v
func TestLiveConnectionCarriesTraffic(t *testing.T) {
	catalogueURL := os.Getenv("WHITEVPN_CATALOGUE_URL")
	catalogueKey := os.Getenv("WHITEVPN_CATALOGUE_KEY")
	if catalogueURL == "" || catalogueKey == "" {
		t.Skip("set WHITEVPN_CATALOGUE_URL and WHITEVPN_CATALOGUE_KEY to run this")
	}

	corePath := enginePath(t)
	subscription := fetchSubscription(t, catalogueURL, catalogueKey)

	direct, err := egressIP(context.Background(), nil)
	if err != nil {
		t.Skipf("no direct internet connection to compare against: %v", err)
	}
	t.Logf("direct egress: %s", direct)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Proxy only. The tunnel path is covered separately, elevated.
	session, err := Connect(ctx, Options{
		CorePath:     corePath,
		HomeDir:      t.TempDir(),
		Subscription: subscription,
		MixedPort:    23080,
		ControlPort:  23090,
		Tun:          mihomoconf.TunOptions{Enabled: false},
		// Unelevated test run; production keeps the default restriction.
		PipeSecurityDescriptor: "D:P(A;;GA;;;WD)",
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	t.Logf("connected: %d proxies, health %d", session.ProxyCount(), session.HealthStatus())
	if session.ProxyCount() < 100 {
		t.Errorf("only %d proxies from the live catalogue", session.ProxyCount())
	}

	// The health gate proves a request completed. It does not prove the request
	// left through a server, which is the part that matters to a user.
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", session.MixedPort()))
	throughProxy, err := egressIP(ctx, http.ProxyURL(proxyURL))
	if err != nil {
		t.Fatalf("no egress through the proxy: %v", err)
	}
	t.Logf("proxied egress: %s", throughProxy)
	if throughProxy == direct {
		t.Fatalf("traffic left from %s, the same address as without the proxy", throughProxy)
	}
}

// A subscription that yields nothing must fail the connection rather than start
// an engine that sits there carrying no traffic.
func TestLiveConnectRefusesAnEmptySubscription(t *testing.T) {
	corePath := enginePath(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := Connect(ctx, Options{
		CorePath:               corePath,
		HomeDir:                t.TempDir(),
		Subscription:           "nothing usable here",
		PipeSecurityDescriptor: "D:P(A;;GA;;;WD)",
	})
	if err == nil {
		t.Fatal("expected a subscription with no proxies to fail")
	}
}

func enginePath(t *testing.T) string {
	t.Helper()
	name := "mihomo-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path, err := filepath.Abs(filepath.Join("..", "..", "cores", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("engine not built (%s); run `make mihomo-core`", name)
	}
	return path
}

func egressIP(ctx context.Context, proxy func(*http.Request) (*url.URL, error)) (string, error) {
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: proxy}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<12))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", response.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}

func fetchSubscription(t *testing.T, target, passphrase string) string {
	t.Helper()
	response, err := (&http.Client{Timeout: 30 * time.Second}).Get(target)
	if err != nil {
		t.Skipf("catalogue unreachable: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}

	var payload struct {
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	iv, err := decodeBase64(payload.IV)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := decodeBase64(payload.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(plaintext)
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

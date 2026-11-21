// Package warp registers a free Cloudflare WARP device and turns it into a
// mihomo WireGuard subscription, the way WhiteVPN for Android does
// (WarpRegistration.kt, 1.8.0-beta.2). The YAML it writes is the phone's, byte
// for byte, so a WARP subscription means the same thing on both.
package warp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// Same device API and client headers as the Android WARP client (see bepass-org/warp-plus).
	RegisterURL         = "https://api.cloudflareclient.com/v0a4005/reg"
	DefaultServer       = "162.159.192.1"
	DefaultPort         = 2408
	Timeout             = 15 * time.Second
	ProxyName           = "WARP"
	CloudflarePublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

// The phone's DEFAULT_NOISE (MihomoConnectionOptionsPolicy) and its fixed TTL.
const (
	noiseCount   = 5
	noiseMinSize = 50
	noiseMaxSize = 100
	noiseTTL     = 3
)

// The only characters an endpoint needs. It is what keeps a user-typed server
// from closing the YAML scalar and writing directives of its own.
var serverPattern = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,253}$`)

func ValidServer(value string) bool { return serverPattern.MatchString(value) }

func ValidPort(port int) bool { return port >= 1 && port <= 65535 }

type Keys struct{ PrivateKey, PublicKey string }

func GenerateKeys() (Keys, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}
	encode := base64.StdEncoding.EncodeToString
	return Keys{PrivateKey: encode(key.Bytes()), PublicKey: encode(key.PublicKey().Bytes())}, nil
}

// RequestBody carries the public key and generic device fields, nothing about the user.
func RequestBody(publicKey string, now time.Time) ([]byte, error) {
	return json.Marshal(struct {
		InstallID   string `json:"install_id"`
		FCMToken    string `json:"fcm_token"`
		TOS         string `json:"tos"`
		Key         string `json:"key"`
		Type        string `json:"type"`
		Model       string `json:"model"`
		Locale      string `json:"locale"`
		WarpEnabled bool   `json:"warp_enabled"`
	}{"", "", now.UTC().Format(time.RFC3339), publicKey, "Android", "PC", "en_US", true})
}

// Register creates a new WARP device at url through client and returns the
// subscription YAML for it.
func Register(ctx context.Context, client *http.Client, url string) (string, error) {
	keys, err := GenerateKeys()
	if err != nil {
		return "", err
	}
	body, err := RequestBody(keys.PublicKey, time.Now())
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("User-Agent", "okhttp/3.12.1")
	request.Header.Set("CF-Client-Version", "a-6.30-3596")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("WARP registration failed with HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return SubscriptionYAML(raw, keys.PrivateKey)
}

// SubscriptionYAML builds the subscription from a `/reg` response.
func SubscriptionYAML(response []byte, privateKey string) (string, error) {
	var reply struct {
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4 string `json:"v4"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.Unmarshal(response, &reply); err != nil {
		return "", fmt.Errorf("WARP response is not readable: %w", err)
	}
	config := reply.Config
	if len(config.Peers) == 0 || strings.TrimSpace(config.Peers[0].PublicKey) == "" {
		return "", fmt.Errorf("WARP response has no peer key")
	}
	if strings.TrimSpace(config.Interface.Addresses.V4) == "" {
		return "", fmt.Errorf("WARP response has no IPv4 address")
	}
	server := config.Peers[0].Endpoint.V4
	if i := strings.LastIndex(server, ":"); i >= 0 {
		server = server[:i]
	}
	if strings.TrimSpace(server) == "" {
		server = DefaultServer
	}
	var reserved []int
	if id, err := base64.StdEncoding.DecodeString(config.ClientID); err == nil && len(id) == 3 {
		reserved = []int{int(id[0]), int(id[1]), int(id[2])}
	}
	return Config{
		Server:     server,
		Port:       DefaultPort,
		PrivateKey: privateKey,
		PublicKey:  config.Peers[0].PublicKey,
		IPv4:       config.Interface.Addresses.V4,
		IPv6:       strings.TrimSpace(config.Interface.Addresses.V6),
		Reserved:   reserved,
		Noise:      true,
	}.YAML()
}

// Config is the editable shape of a WARP subscription; keys and addresses stay
// as Cloudflare issued them.
type Config struct {
	Server     string
	Port       int
	PrivateKey string
	PublicKey  string
	IPv4       string
	IPv6       string
	Reserved   []int
	Noise      bool
}

// YAML is Android's WarpConfig.toYaml through MihomoLinkConfigBuilder.build:
// one proxy, then the default select and url-test groups and the MATCH rule.
// The desktop reads only `proxies` from it; the rest keeps the text the phone's.
func (c Config) YAML() (string, error) {
	if !ValidServer(c.Server) {
		return "", fmt.Errorf("WARP server %q is not an IP address or host name", c.Server)
	}
	if !ValidPort(c.Port) {
		return "", fmt.Errorf("WARP port must be between 1 and 65535")
	}
	// Single-quoted scalars cannot carry a line break safely, and the keys and
	// addresses arrive from the network.
	for _, value := range []string{c.PrivateKey, c.PublicKey, c.IPv4, c.IPv6} {
		if strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("WARP configuration contains a line break")
		}
	}
	if c.PrivateKey == "" || c.PublicKey == "" || c.IPv4 == "" {
		return "", fmt.Errorf("WARP configuration is incomplete")
	}
	ipVersion := "ipv4"
	if c.IPv6 != "" {
		ipVersion = "ipv4-prefer"
	}
	var b strings.Builder
	line := func(prefix, key, value string) { b.WriteString(prefix + key + ": " + value + "\n") }
	b.WriteString("proxies:\n")
	line("  - ", "name", quote(ProxyName))
	line("    ", "type", quote("wireguard"))
	line("    ", "server", quote(c.Server))
	line("    ", "port", strconv.Itoa(c.Port))
	line("    ", "ip", quote(c.IPv4))
	line("    ", "ip-version", quote(ipVersion))
	line("    ", "private-key", quote(c.PrivateKey))
	line("    ", "public-key", quote(c.PublicKey))
	line("    ", "allowed-ips", "['0.0.0.0/0', '::/0']")
	line("    ", "udp", "true")
	line("    ", "mtu", "1280")
	if c.IPv6 != "" {
		line("    ", "ipv6", quote(c.IPv6))
	}
	if len(c.Reserved) == 3 {
		line("    ", "reserved", fmt.Sprintf("[%d, %d, %d]", c.Reserved[0], c.Reserved[1], c.Reserved[2]))
	}
	// Plain WARP handshakes are blocked in Iran; fake packets before the handshake help it through.
	if c.Noise {
		line("    ", "wireguard-dpi-option", fmt.Sprintf("{'fake-count': %d, 'fake-min-size': %d, 'fake-max-size': %d, 'fake-ttl': %d}",
			noiseCount, noiseMinSize, noiseMaxSize, noiseTTL))
	}
	b.WriteString(`proxy-groups:
  - name: 'WhiteDNS Proxy'
    type: select
    proxies:
      - 'WhiteDNS Auto'
      - 'WARP'
  - name: 'WhiteDNS Auto'
    type: url-test
    url: 'https://connectivitycheck.gstatic.com/generate_204'
    interval: 300
    tolerance: 100
    proxies:
      - 'WARP'
rules:
  - 'MATCH,WhiteDNS Proxy'
`)
	return b.String(), nil
}

func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

// Parse reads a subscription made by this package or by the phone. Anything
// else — more than one proxy, not WireGuard, not Cloudflare's peer and not
// named WARP — is not a WARP subscription.
func Parse(body string) (Config, bool) {
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(body), &document); err != nil || len(document.Proxies) != 1 {
		return Config{}, false
	}
	proxy := document.Proxies[0]
	text := func(key string) string { value, _ := proxy[key].(string); return value }
	if !strings.EqualFold(text("type"), "wireguard") {
		return Config{}, false
	}
	publicKey := text("public-key")
	if publicKey == "" || (publicKey != CloudflarePublicKey && text("name") != ProxyName) {
		return Config{}, false
	}
	port, _ := proxy["port"].(int)
	config := Config{
		Server:     text("server"),
		Port:       port,
		PrivateKey: text("private-key"),
		PublicKey:  publicKey,
		IPv4:       text("ip"),
		IPv6:       text("ipv6"),
		Noise:      proxy["wireguard-dpi-option"] != nil,
	}
	if config.Server == "" || port == 0 || config.PrivateKey == "" || config.IPv4 == "" {
		return Config{}, false
	}
	if values, ok := proxy["reserved"].([]any); ok && len(values) == 3 {
		for _, value := range values {
			number, ok := value.(int)
			if !ok {
				config.Reserved = nil
				break
			}
			config.Reserved = append(config.Reserved, number)
		}
	}
	return config, true
}

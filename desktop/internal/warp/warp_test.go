package warp

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const sampleResponse = `{"id":"d","token":"t","config":{
  "client_id":"AQID",
  "peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
    "endpoint":{"v4":"162.159.192.5:0","v6":"[2606:4700:d0::a29f:c005]:0","host":"engage.cloudflareclient.com:2408"}}],
  "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8a36::1"}}}}`

func TestGeneratedPublicKeyMatchesPrivateKey(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.DecodeString(keys.PrivateKey)
	if err != nil || len(private) != 32 {
		t.Fatalf("private key = %d bytes, %v", len(private), err)
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if derived := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()); derived != keys.PublicKey {
		t.Fatalf("public key %q does not belong to the private key (%q)", keys.PublicKey, derived)
	}
}

func TestRequestBodyCarriesOnlyTheKeyAndGenericDeviceFields(t *testing.T) {
	raw, err := RequestBody("pub", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"install_id":"","fcm_token":"","tos":"2026-11-20T00:00:00Z","key":"pub","type":"Android","model":"PC","locale":"en_US","warp_enabled":true}`
	if string(raw) != want {
		t.Fatalf("body = %s\nwant  %s", raw, want)
	}
}

func TestRegistrationResponseBecomesOneWireGuardConnection(t *testing.T) {
	yaml, err := SubscriptionYAML([]byte(sampleResponse), "cHJpdmF0ZQ==")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  - name: 'WARP'\n    type: 'wireguard'\n    server: '162.159.192.5'\n    port: 2408\n",
		"ip: '172.16.0.2'", "ipv6: '2606:4700:110:8a36::1'", "ip-version: 'ipv4-prefer'",
		"private-key: 'cHJpdmF0ZQ=='", "public-key: '" + CloudflarePublicKey + "'",
		"allowed-ips: ['0.0.0.0/0', '::/0']", "udp: true", "mtu: 1280",
		"wireguard-dpi-option: {'fake-count': 5, 'fake-min-size': 50, 'fake-max-size': 100, 'fake-ttl': 3}",
		"  - name: 'WhiteDNS Proxy'\n    type: select\n", "rules:\n  - 'MATCH,WhiteDNS Proxy'\n",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("YAML lacks %q:\n%s", want, yaml)
		}
	}
	if !regexp.MustCompile(`reserved:\s*\[\s*1,\s*2,\s*3\s*]`).MatchString(yaml) {
		t.Errorf("reserved missing:\n%s", yaml)
	}
}

func TestRegistrationResponseDefaults(t *testing.T) {
	// No endpoint, no IPv6, and a client id that is not three bytes.
	yaml, err := SubscriptionYAML([]byte(`{"config":{"client_id":"AQIDBA==","peers":[{"public_key":"peer"}],
		"interface":{"addresses":{"v4":"172.16.0.2"}}}}`), "key")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, "server: '"+DefaultServer+"'") || !strings.Contains(yaml, "ip-version: 'ipv4'\n") {
		t.Fatalf("defaults not applied:\n%s", yaml)
	}
	if strings.Contains(yaml, "ipv6:") || strings.Contains(yaml, "reserved:") {
		t.Fatalf("absent fields were written:\n%s", yaml)
	}
	for _, response := range []string{
		`{"config":{"peers":[],"interface":{"addresses":{"v4":"172.16.0.2"}}}}`,
		`{"config":{"peers":[{"public_key":"peer"}],"interface":{"addresses":{}}}}`,
		`{"config":{"peers":[{"public_key":"peer"}],"interface":{"addresses":{"v4":"1.1.1.1\n  type: x"}}}}`,
		`not json`,
	} {
		if _, err := SubscriptionYAML([]byte(response), "key"); err == nil {
			t.Errorf("accepted %s", response)
		}
	}
}

func TestConfigSurvivesFieldEdits(t *testing.T) {
	original := Config{Server: "162.159.192.5", Port: 2408, PrivateKey: "cHJpdmF0ZQ==", PublicKey: CloudflarePublicKey,
		IPv4: "172.16.0.2", IPv6: "2606:4700:110:8a36::1", Reserved: []int{1, 2, 3}, Noise: true}
	roundTrip := func(c Config) Config {
		t.Helper()
		yaml, err := c.YAML()
		if err != nil {
			t.Fatal(err)
		}
		parsed, ok := Parse(yaml)
		if !ok {
			t.Fatalf("did not parse back:\n%s", yaml)
		}
		return parsed
	}
	if got := roundTrip(original); !reflect.DeepEqual(got, original) {
		t.Fatalf("round trip = %#v", got)
	}
	edited := original
	edited.Server, edited.Port, edited.Noise = "188.114.97.3", 894, false
	got := roundTrip(edited)
	if !reflect.DeepEqual(got, edited) {
		t.Fatalf("edit round trip = %#v", got)
	}
	if got.PrivateKey != original.PrivateKey || got.PublicKey != original.PublicKey || got.IPv4 != original.IPv4 || got.IPv6 != original.IPv6 || !reflect.DeepEqual(got.Reserved, original.Reserved) {
		t.Fatal("edit changed the keys or addresses")
	}
	if yaml, _ := edited.YAML(); strings.Contains(yaml, "wireguard-dpi-option") {
		t.Fatal("noise off still writes the DPI option")
	}
}

func TestParseRefusesOtherSubscriptions(t *testing.T) {
	for _, body := range []string{
		"proxies:\n  - name: 'x'\n    type: vless\n    server: a.example\n    port: 443\n",
		"proxies:\n  - {name: wg, type: wireguard, server: a.example, port: 1, ip: 10.0.0.2, private-key: k, public-key: other}\n",
		"proxies:\n  - {name: WARP, type: wireguard, server: a, port: 1, ip: 10.0.0.2, private-key: k, public-key: p}\n  - {name: b, type: wireguard, server: a, port: 1, ip: 10.0.0.2, private-key: k, public-key: p}\n",
		"vless://x@a.example:443#x",
	} {
		if _, ok := Parse(body); ok {
			t.Errorf("parsed as WARP: %q", body)
		}
	}
	// Either the Cloudflare peer or the name is enough.
	if _, ok := Parse("proxies:\n  - {name: wg, type: wireguard, server: a, port: 1, ip: 10.0.0.2, private-key: k, public-key: '" + CloudflarePublicKey + "'}\n"); !ok {
		t.Error("Cloudflare peer under another name not recognised")
	}
}

func TestServerValidationBlocksYAMLInjection(t *testing.T) {
	for _, valid := range []string{"162.159.192.1", "engage.cloudflareclient.com", "[2606:4700:d0::a29f:c005]", "2606:4700::1"} {
		if !ValidServer(valid) {
			t.Errorf("rejected %q", valid)
		}
	}
	for _, invalid := range []string{"", "1.1.1.1\n  type: x", "1.1.1.1 type: vless", "a'b", "a#b", strings.Repeat("a", 254)} {
		if ValidServer(invalid) {
			t.Errorf("accepted %q", invalid)
		}
		if _, err := (Config{Server: invalid, Port: 2408, PrivateKey: "k", PublicKey: "p", IPv4: "172.16.0.2"}).YAML(); err == nil {
			t.Errorf("YAML built with server %q", invalid)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := (Config{Server: "1.1.1.1", Port: port, PrivateKey: "k", PublicKey: "p", IPv4: "172.16.0.2"}).YAML(); err == nil {
			t.Errorf("YAML built with port %d", port)
		}
	}
}

func TestRegisterSendsTheDeviceRequest(t *testing.T) {
	var sentKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v0a4005/reg" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		for header, want := range map[string]string{
			"Content-Type": "application/json; charset=UTF-8", "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.30-3596",
		} {
			if got := r.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		sentKey, _ = body["key"].(string)
		_, _ = io.WriteString(w, sampleResponse)
	}))
	defer server.Close()

	yaml, err := Register(context.Background(), server.Client(), server.URL+"/v0a4005/reg")
	if err != nil {
		t.Fatal(err)
	}
	config, ok := Parse(yaml)
	if !ok {
		t.Fatalf("registration YAML is not WARP:\n%s", yaml)
	}
	private, _ := base64.StdEncoding.DecodeString(config.PrivateKey)
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != sentKey {
		t.Fatal("the stored private key does not match the public key that was registered")
	}
}

func TestRegisterFailsOnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	}))
	defer server.Close()
	if _, err := Register(context.Background(), server.Client(), server.URL); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v", err)
	}
}

package mihomoconf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Converting a handful of hand-written links proves the parser reads what it was
// told to read. It does not prove the parser survives a real subscription, where
// the same four schemes arrive in shapes nobody wrote down: base64 hosts,
// percent-encoded names, transports paired with options they do not use.
//
// This test runs against the live catalogue when given credentials, and is
// skipped otherwise, so it never becomes a reason CI depends on the network.
// Credentials come from the environment rather than the repository:
//
//	WHITEVPN_CATALOGUE_URL=... WHITEVPN_CATALOGUE_KEY=... go test ./internal/mihomoconf -run Catalogue -v
func TestLiveCatalogueConverts(t *testing.T) {
	url := os.Getenv("WHITEVPN_CATALOGUE_URL")
	key := os.Getenv("WHITEVPN_CATALOGUE_KEY")
	if url == "" || key == "" {
		t.Skip("set WHITEVPN_CATALOGUE_URL and WHITEVPN_CATALOGUE_KEY to run this")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Skipf("catalogue unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}

	plain, err := decryptCatalogue(string(body), key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	proxies, err := ConvertLinks(plain)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	// mihomo keys proxies by name, so a duplicate does not produce two nodes —
	// it produces one, silently, and the user loses a server they can see listed.
	names := map[string]bool{}
	for _, proxy := range proxies {
		if names[proxy.Name()] {
			t.Errorf("duplicate proxy name %q", proxy.Name())
		}
		names[proxy.Name()] = true

		// Every proxy must be addressable and typed, or mihomo will reject the
		// whole config rather than the one bad entry.
		if str(proxy["type"]) == "" || str(proxy["server"]) == "" {
			t.Errorf("incomplete proxy: %#v", proxy)
		}
		if port, ok := proxy["port"].(int); !ok || port < 1 || port > 65535 {
			t.Errorf("bad port on %q: %#v", proxy.Name(), proxy["port"])
		}
	}

	byType := map[string]int{}
	for _, proxy := range proxies {
		byType[str(proxy["type"])]++
	}
	t.Logf("converted %d proxies from the live catalogue: %v", len(proxies), byType)

	if len(proxies) < 100 {
		t.Errorf("only %d proxies converted; the catalogue is much larger than that", len(proxies))
	}
}

func decryptCatalogue(rawText, passphrase string) (string, error) {
	var payload struct {
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawText)), &payload); err != nil {
		return "", err
	}
	iv, err := decodeB64(payload.IV)
	if err != nil {
		return "", err
	}
	ciphertext, err := decodeB64(payload.Ciphertext)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	return string(plaintext), err
}

func decodeB64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func str(value any) string {
	s, _ := value.(string)
	return s
}

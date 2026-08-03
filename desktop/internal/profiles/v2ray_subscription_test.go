package profiles

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseV2RaySubscriptionDocumentParsesPlainLinks(t *testing.T) {
	raw := "ss://unsupported\n" + testV2RaySubscriptionVLESSLink("plain")

	profiles, err := ParseV2RaySubscriptionDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one V2Ray profile, got %d", len(profiles))
	}
	if profiles[0].Server != "plain.example.com" {
		t.Fatalf("unexpected profile: %#v", profiles[0])
	}
}

func TestParseV2RaySubscriptionDocumentParsesBase64Links(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(testV2RaySubscriptionVLESSLink("encoded")))

	profiles, err := ParseV2RaySubscriptionDocument(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one V2Ray profile, got %d", len(profiles))
	}
	if profiles[0].Server != "encoded.example.com" {
		t.Fatalf("unexpected profile: %#v", profiles[0])
	}
}

func TestParseV2RaySubscriptionDocumentSkipsMalformedLinks(t *testing.T) {
	raw := "vless://@bad.example.com:443?type=ws#Bad\n" + testV2RaySubscriptionVLESSLink("valid")

	profiles, err := ParseV2RaySubscriptionDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Server != "valid.example.com" {
		t.Fatalf("expected malformed subscription link to be skipped, got %#v", profiles)
	}
}

func TestParseV2RaySubscriptionDocumentParsesBase64VLESSAndTrojanLinks(t *testing.T) {
	raw := strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@[2606:4700:310c::ac42:2efa]:443?encryption=none&host=cdn.example.com&type=ws&security=tls&path=%2Fws&sni=front.example.com&fp=randomized&alpn=http%2F1.1#VLESS",
		"trojan://secret%40value@example.net:443?host=cdn.example.com&type=ws&security=tls&path=%2Ftrojan&sni=front.example.com#Trojan",
	}, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	profiles, err := ParseV2RaySubscriptionDocument(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected two decoded profiles, got %d", len(profiles))
	}
	if profiles[0].Server != "2606:4700:310c::ac42:2efa" || profiles[0].Network != "ws" || profiles[0].TransportHost != "cdn.example.com" {
		t.Fatalf("unexpected decoded VLESS profile: %#v", profiles[0])
	}
	if profiles[1].Protocol != "trojan" || profiles[1].Password != "secret@value" || profiles[1].TransportPath != "/trojan" {
		t.Fatalf("unexpected decoded Trojan profile: %#v", profiles[1])
	}
}

func TestParseV2RaySubscriptionDocumentRejectsUnsupportedLinks(t *testing.T) {
	_, err := ParseV2RaySubscriptionDocument("ss://unsupported")
	if err == nil {
		t.Fatal("expected unsupported subscription to fail")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testV2RaySubscriptionVLESSLink(name string) string {
	return "vless://11111111-1111-1111-1111-111111111111@" + name + ".example.com:443?security=tls&type=tcp#" + name
}

package profiles

import (
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestParseWhiteIPEndpointsIgnoresMetadataAndDeduplicates(t *testing.T) {
	endpoints, err := ParseWhiteIPEndpoints(`
# WhiteDNS IP lists
[cloudflare]
69.84.182.49:443
104.17.121.71:443
69.84.182.49:443

; backup
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %#v", endpoints)
	}
	if endpoints[0].Host != "69.84.182.49" || endpoints[0].Port != 443 {
		t.Fatalf("unexpected first endpoint: %#v", endpoints[0])
	}
	if endpoints[1].Host != "104.17.121.71" || endpoints[1].Port != 443 {
		t.Fatalf("unexpected second endpoint: %#v", endpoints[1])
	}
}

func TestParseWhiteIPEndpointsRejectsInvalidEntries(t *testing.T) {
	tests := []string{
		"69.84.182.49",
		"69.84.182.49:0",
		"69.84.182.49:70000",
		"69.84.182.49:https",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseWhiteIPEndpoints(raw); err == nil {
				t.Fatal("expected invalid endpoint to be rejected")
			}
		})
	}
}

func TestConvertV2RayProfilesToWhiteIPsReplacesServerAndPreservesFields(t *testing.T) {
	profiles, sourceCount, endpointCount, err := ConvertV2RayProfilesToWhiteIPs(
		"vless://11111111-1111-1111-1111-111111111111@origin.example.com:443?security=tls&type=ws&path=/ws#Origin",
		"69.84.182.49:443\n104.17.121.71:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if sourceCount != 1 || endpointCount != 2 || len(profiles) != 2 {
		t.Fatalf("unexpected conversion counts: source=%d endpoints=%d profiles=%d", sourceCount, endpointCount, len(profiles))
	}
	first := profiles[0]
	if first.Server != "69.84.182.49" || first.ServerPort != 443 || first.UUID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("unexpected converted VLESS profile: %#v", first)
	}
	if first.Name != "Origin - 69.84.182.49:443" {
		t.Fatalf("unexpected converted profile name: %q", first.Name)
	}
	if first.SNI != "origin.example.com" || first.TransportHost != "origin.example.com" {
		t.Fatalf("expected original hostname fallback, got sni=%q host=%q", first.SNI, first.TransportHost)
	}
	if first.TransportPath != "/ws" || first.Network != "ws" || !first.TLS {
		t.Fatalf("expected transport fields to be preserved: %#v", first)
	}
	second := profiles[1]
	if second.Server != "104.17.121.71" || second.ServerPort != 8443 {
		t.Fatalf("unexpected second endpoint replacement: %#v", second)
	}
}

func TestConvertV2RayProfilesToWhiteIPsDoesNotOverwriteExplicitSNIOrHost(t *testing.T) {
	profiles, _, _, err := ConvertV2RayProfilesToWhiteIPs(
		"vless://11111111-1111-1111-1111-111111111111@origin.example.com:443?security=tls&type=ws&sni=front.example.com&host=cdn.example.com#Origin",
		"69.84.182.49:443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := profiles[0]; got.SNI != "front.example.com" || got.TransportHost != "cdn.example.com" {
		t.Fatalf("expected explicit SNI and host to be preserved, got %#v", got)
	}
}

func TestConvertV2RayProfilesToWhiteIPsMultipliesSourceProfilesByEndpoints(t *testing.T) {
	raw := strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@one.example.com:443?security=tls&type=tcp#One",
		"trojan://secret@two.example.com:443?security=tls&type=tcp#Two",
	}, "\n")
	profiles, sourceCount, endpointCount, err := ConvertV2RayProfilesToWhiteIPs(raw, "69.84.182.49:443\n104.17.121.71:443")
	if err != nil {
		t.Fatal(err)
	}
	if sourceCount != 2 || endpointCount != 2 || len(profiles) != 4 {
		t.Fatalf("unexpected conversion counts: source=%d endpoints=%d profiles=%d", sourceCount, endpointCount, len(profiles))
	}
	if profiles[0].Protocol != model.V2RayProtocolVLESS || profiles[2].Protocol != model.V2RayProtocolTrojan {
		t.Fatalf("expected source profile order to be preserved: %#v", profiles)
	}
}

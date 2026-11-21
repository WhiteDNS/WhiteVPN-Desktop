package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func publicStateFixture() AppState {
	s := DefaultAppState()
	s.ConnectionProfiles[0].EncryptionKey = "DNS-sensitive-marker"
	s.SettingsProfiles[0].SOCKSUsername = "SOCKS-user-sensitive-marker"
	s.SettingsProfiles[0].SOCKSPassword = "SOCKS-password-sensitive-marker"
	s.V2RayProfiles = []V2RayProfile{{ID: "manual", Name: "Visible name", Protocol: V2RayProtocolVLESS, Server: "localhost", ServerPort: 443,
		UUID: "UUID-sensitive-marker", Password: "password-sensitive-marker", Username: "username-sensitive-marker", HysteriaAuth: "auth-sensitive-marker",
		WireGuardSecretKey: "WG-sensitive-marker", WireGuardPreSharedKey: "PSK-sensitive-marker", RealityShortID: "short-id-sensitive-marker",
		HTTPHeaders: "header-sensitive-marker", OutboundSettings: "outbound-sensitive-marker", StreamSettings: "stream-sensitive-marker", XHTTPExtra: "extra-sensitive-marker",
		TransportPath: "path-sensitive-marker", ServiceName: "service-sensitive-marker", HysteriaMasquerade: "masquerade-sensitive-marker"}}
	s.V2RaySubscriptions = []V2RaySubscription{{ID: "provider", Name: "Visible subscription", URL: "https://user-sensitive-marker:pass-sensitive-marker@provider.example/path-sensitive-marker?token=query-sensitive-marker", LastError: "Get https://provider.example/path-sensitive-marker: failed"}}
	s.WhiteVPN.DNSPrivacy.DoHURL = "https://dns.example/doh-sensitive-marker?token=dns-sensitive-marker"
	s.WhiteVPN.DNSPrivacy.DoTEndpoint = "tls://dot-sensitive-marker@dns.example:853"
	s.Runtime.Logs = []string{"request https://provider.example/runtime-sensitive-marker failed"}
	return s
}

func assertNoSensitiveMarker(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sensitive-marker") {
		t.Fatal("public serialization contains sensitive material")
	}
	return raw
}

func TestPublicStateRedactsAllCredentialInventoryAndKeepsMetadata(t *testing.T) {
	s := publicStateFixture()
	raw := assertNoSensitiveMarker(t, s)
	if !strings.Contains(string(raw), "Visible name") || !strings.Contains(string(raw), "https://provider.example") {
		t.Fatal("metadata disappeared")
	}
	p := s.Public()
	if !p.V2RayProfiles[0].CredentialsReady || !p.V2RayProfiles[0].PublicOnly {
		t.Fatal("public readiness metadata is wrong")
	}
	if s.V2RayProfiles[0].UUID == "" || s.ConnectionProfiles[0].EncryptionKey == "" || s.V2RaySubscriptions[0].URL == "" {
		t.Fatal("redaction mutated private state")
	}
	var roundTrip AppState
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	second := assertNoSensitiveMarker(t, roundTrip)
	if string(raw) != string(second) {
		t.Fatal("public serialization is not idempotent")
	}
	assertNoSensitiveMarker(t, V2RaySubscriptionRefreshResult{State: s, Subscription: s.V2RaySubscriptions[0], Message: "error https://provider.example/result-sensitive-marker"})
}

func TestPublicStateSnapshotCannotMutatePrivateSlicesOrMaps(t *testing.T) {
	s := publicStateFixture()
	s.HiddenNodes = map[string][]string{"provider": {"Hidden"}}
	s.WhiteVPN.Connection.Types = []string{"vless"}
	s.WhiteVPN.SubscriptionSelections = map[string]SubscriptionSelection{"other": {Connection: ConnectionSelection{Types: []string{"trojan"}}}}
	s.ResolverProfiles[0].ResolverPreview = []string{"1.1.1.1"}
	s.Runtime.ResolverState.ActiveResolvers = []string{"1.1.1.1"}
	s.Runtime.ResolverState.ResolverDetails = []ResolverRuntimeDetail{{Resolver: "1.1.1.1", Cause: "Original"}}
	p := s.Public()
	p.HiddenNodes["provider"][0] = "Changed"
	p.WhiteVPN.Connection.Types[0] = "Changed"
	parked := p.WhiteVPN.SubscriptionSelections["other"]
	parked.Connection.Types[0] = "Changed"
	p.ResolverProfiles[0].ResolverPreview[0] = "Changed"
	p.V2RayProfiles[0].Name = "Changed"
	p.Runtime.ResolverState.ActiveResolvers[0] = "Changed"
	p.Runtime.ResolverState.ResolverDetails[0].Cause = "Changed"
	if s.HiddenNodes["provider"][0] != "Hidden" || s.WhiteVPN.Connection.Types[0] != "vless" || s.WhiteVPN.SubscriptionSelections["other"].Connection.Types[0] != "trojan" || s.ResolverProfiles[0].ResolverPreview[0] != "1.1.1.1" || s.V2RayProfiles[0].Name != "Visible name" {
		t.Fatal("public snapshot shares mutable storage")
	}
	if s.Runtime.ResolverState.ActiveResolvers[0] != "1.1.1.1" || s.Runtime.ResolverState.ResolverDetails[0].Cause != "Original" {
		t.Fatal("public runtime shares mutable resolver storage")
	}
}

func TestBackupStateMarksOmittedDetailsAndDoesNotNormalizeThemToDefaults(t *testing.T) {
	s := publicStateFixture()
	b := s.BackupState()
	assertNoSensitiveMarker(t, b)
	if !b.ConnectionProfiles[0].CredentialRequired || !b.SettingsProfiles[0].CredentialRequired || !b.V2RayProfiles[0].CredentialRequired || !b.V2RaySubscriptions[0].CredentialRequired || !b.WhiteVPN.DNSPrivacy.CredentialRequired {
		t.Fatal("omitted credentials not marked")
	}
	if b.V2RayProfiles[0].PublicOnly || V2RayCredentialsReady(b.V2RayProfiles[0]) {
		t.Fatal("restored placeholder is treated as ready")
	}
	normalized := NormalizeWhiteVPNSettings(b.WhiteVPN)
	if normalized.DNSPrivacy.DoHURL != "" || normalized.DNSPrivacy.DoTEndpoint != "" {
		t.Fatal("missing custom DNS changed to a different service")
	}
}

func TestNodeAndRuntimeEventsDoNotExposeShareLinksOrTokenURLs(t *testing.T) {
	n := WhiteVPNNode{Name: "Node", Link: "vless://UUID-sensitive-marker@localhost:443", DelayError: "Get https://test.example/error-sensitive-marker failed"}
	raw := assertNoSensitiveMarker(t, WhiteVPNNodeList{Nodes: []WhiteVPNNode{n}})
	if !strings.Contains(string(raw), `"shareAvailable":true`) {
		t.Fatal("share availability lost")
	}
	if n.Link == "" {
		t.Fatal("wire serialization changed internal node")
	}
	assertNoSensitiveMarker(t, RuntimeLogEntry{Line: "vmess://runtime-sensitive-marker"})
	assertNoSensitiveMarker(t, RuntimeStatus{Message: "request https://api.example/message-sensitive-marker", Logs: []string{"https://api.example/log-sensitive-marker"}})
	assertNoSensitiveMarker(t, RuntimeStatus{TrafficMonitorMessage: "tls://user-sensitive-marker@dns.example:853", ResolverState: ResolverRuntimeState{ResolverDetails: []ResolverRuntimeDetail{{Cause: "https://resolver.example/cause-sensitive-marker"}}}})
}

func TestPublicSettingsRequiredArraysSerializeEmptyRatherThanNull(t *testing.T) {
	p := DefaultAppState().Public()
	settings := p.WhiteVPN
	for name, values := range map[string][]string{"connection types": settings.Connection.Types, "split processes": settings.SplitTunnel.Processes, "fronting IPs": settings.FrontingIPs, "direct domains": settings.DirectRouting.Domains, "direct IPs": settings.DirectRouting.IPs} {
		if values == nil {
			t.Fatalf("required UI array %s is null", name)
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip AppState
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.WhiteVPN.Connection.Types == nil || roundTrip.WhiteVPN.FrontingIPs == nil {
		t.Fatal("wire round trip changed required arrays to null")
	}
}

func TestPublicSubscriptionHidesAnInlineBodyAndSaysThereIsOne(t *testing.T) {
	sub := PublicSubscription(V2RaySubscription{ID: "warp", Name: "WARP", Body: "private-key: 'body-sensitive-marker'"})
	assertNoSensitiveMarker(t, sub)
	if !sub.Inline || !PublicSubscription(sub).Inline {
		t.Fatal("public subscription lost the inline marker")
	}
	s := DefaultAppState()
	s.V2RaySubscriptions = []V2RaySubscription{{ID: "warp", Name: "WARP", Body: "body-sensitive-marker"}}
	assertNoSensitiveMarker(t, s)
	assertNoSensitiveMarker(t, s.BackupState())
}

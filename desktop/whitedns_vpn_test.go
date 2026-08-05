package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestDecryptWhiteDNSVPNSubscription(t *testing.T) {
	plaintext := base64.StdEncoding.EncodeToString([]byte(testV2RaySubscriptionLink("encrypted")))
	encrypted := encryptWhiteDNSVPNTestPayload(t, plaintext)

	decrypted, err := decryptWhiteDNSVPNSubscription(encrypted, whiteDNSVPNSubscriptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Fatal("decrypted subscription did not match plaintext")
	}
}

func TestDecryptWhiteDNSVPNFrontingIPList(t *testing.T) {
	encrypted := encryptWhiteDNSVPNTestPayloadWithKey(t, `["203.0.113.10","bad","203.0.113.10","198.51.100.20"]`, whiteDNSVPNFrontingIPListKey)

	decrypted, err := decryptWhiteDNSVPNIPList(encrypted, whiteDNSVPNFrontingIPListKey)
	if err != nil {
		t.Fatal(err)
	}
	ips, err := parseWhiteDNSVPNFrontingIPs(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 || ips[0] != "203.0.113.10" || ips[1] != "198.51.100.20" {
		t.Fatalf("unexpected parsed IPs: %#v", ips)
	}
}

func TestParseWhiteDNSVPNCustomFrontingIPs(t *testing.T) {
	ips, err := parseWhiteDNSVPNCustomFrontingIPs(" 104.16.0.10,104.16.0.11,104.16.0.10 ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ips, ",") != "104.16.0.10,104.16.0.11" {
		t.Fatalf("unexpected custom IPs: %#v", ips)
	}
	if _, err := parseWhiteDNSVPNCustomFrontingIPs("104.16.0.10 104.16.0.11"); err == nil {
		t.Fatal("expected whitespace-separated IPs to be rejected")
	}
	if _, err := parseWhiteDNSVPNCustomFrontingIPs("104.16.0.1,104.16.0.2,104.16.0.3,104.16.0.4,104.16.0.5,104.16.0.6,104.16.0.7,104.16.0.8,104.16.0.9,104.16.0.10"); err != nil {
		t.Fatalf("expected ten IPs to be accepted: %v", err)
	}
	if _, err := parseWhiteDNSVPNCustomFrontingIPs("104.16.0.1,104.16.0.2,104.16.0.3,104.16.0.4,104.16.0.5,104.16.0.6,104.16.0.7,104.16.0.8,104.16.0.9,104.16.0.10,104.16.0.11"); err == nil {
		t.Fatal("expected more than ten IPs to be rejected")
	}
}

func encryptWhiteDNSVPNTestPayload(t *testing.T, plaintext string) string {
	t.Helper()
	return encryptWhiteDNSVPNTestPayloadWithKey(t, plaintext, whiteDNSVPNSubscriptionKey)
}

func encryptWhiteDNSVPNTestPayloadWithKey(t *testing.T, plaintext string, keyText string) string {
	t.Helper()
	key := sha256.Sum256([]byte(keyText))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	if len(nonce) != gcm.NonceSize() {
		t.Fatal("test nonce size mismatch")
	}
	payload, err := json.Marshal(whiteDNSVPNEncryptedPayload{
		Version:    1,
		Algorithm:  "AES-GCM",
		Encoding:   "base64url",
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, []byte(plaintext), nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func testWhiteDNSVPNFrontingProfile() model.V2RayProfile {
	return testWhiteDNSVPNProfile("white-fronting", "WhiteDNS Fronting", "origin.example.com")
}

func testWhiteDNSVPNProfile(id string, name string, server string) model.V2RayProfile {
	profile := model.DefaultV2RayProfile()
	profile.ID = id
	profile.Name = name
	profile.SubscriptionID = whiteDNSVPNSubscriptionID
	profile.Protocol = model.V2RayProtocolVLESS
	profile.Server = server
	profile.ServerPort = 443
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "ws"
	profile.TLS = true
	return profile
}

func firstWhiteDNSVPNOutbound(t *testing.T, config string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(config), &root); err != nil {
		t.Fatal(err)
	}
	outbounds := root["outbounds"].([]any)
	return outbounds[0].(map[string]any)
}

func whiteDNSVPNTestProfiles(profiles []model.V2RayProfile) []model.V2RayProfile {
	var out []model.V2RayProfile
	for _, profile := range profiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			out = append(out, profile)
		}
	}
	return out
}

// The built-in catalogue's address is the app's, not the user's. It is a
// constant here and must never reach the state, because everything the user can
// see — the subscriptions list, a backup export, the state handed to the
// interface — is built from that.
func TestBuiltInCatalogueAddressNeverEntersState(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.mu.Lock()
	idx := app.ensureWhiteDNSVPNSubscriptionLocked()
	app.mu.Unlock()

	if got := app.state.V2RaySubscriptions[idx].URL; got != "" {
		t.Fatalf("the catalogue address was stored: %q", got)
	}
	if app.state.V2RaySubscriptions[idx].ID != whiteDNSVPNSubscriptionID {
		t.Fatalf("expected the built-in subscription, got %#v", app.state.V2RaySubscriptions[idx])
	}

	raw, err := json.Marshal(app.state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), whiteDNSVPNSubscriptionURL) {
		t.Fatal("the catalogue address is reachable through the serialised state")
	}
}

// A state file written before that was true, or a restored backup, still has it.
func TestForgetBuiltInSubscriptionURLClearsAnOlderState(t *testing.T) {
	state := model.DefaultAppState()
	state.V2RaySubscriptions = []model.V2RaySubscription{
		{ID: whiteDNSVPNSubscriptionID, Name: whiteDNSVPNSubscriptionName, URL: whiteDNSVPNSubscriptionURL},
		{ID: "user-1", Name: "Mine", URL: "https://example.com/sub"},
	}

	next := forgetBuiltInSubscriptionURL(state)

	if next.V2RaySubscriptions[0].URL != "" {
		t.Fatalf("expected the built-in address to be dropped, got %q", next.V2RaySubscriptions[0].URL)
	}
	if next.V2RaySubscriptions[1].URL != "https://example.com/sub" {
		t.Fatalf("a subscription the user added is theirs and must be left alone, got %q", next.V2RaySubscriptions[1].URL)
	}
}

func TestBuiltInCatalogueRefusesEditAndDeletion(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.mu.Lock()
	app.ensureWhiteDNSVPNSubscriptionLocked()
	app.mu.Unlock()

	if _, err := app.SaveV2RaySubscription(model.V2RaySubscription{ID: whiteDNSVPNSubscriptionID, Name: "Mine", URL: "https://evil.example"}); err == nil {
		t.Fatal("expected editing the built-in catalogue to be refused")
	}
	if _, err := app.DeleteV2RaySubscription(whiteDNSVPNSubscriptionID); err == nil {
		t.Fatal("expected removing the built-in catalogue to be refused")
	}
	if _, ok := findV2RaySubscription(app.state, whiteDNSVPNSubscriptionID); !ok {
		t.Fatal("the built-in catalogue should still be listed")
	}
}

func TestPrivacyPolicyGateBlocksConnectingUntilAccepted(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	if privacyPolicyAccepted(app.GetAppState()) {
		t.Fatal("a fresh install has accepted nothing")
	}
	if _, err := app.StartWhiteDNSVPNConnection(); err == nil {
		t.Fatal("expected connecting to be refused before the policy is accepted")
	}

	if _, err := app.AcceptPrivacyPolicy(); err != nil {
		t.Fatal(err)
	}
	state := app.GetAppState()
	if state.WhiteVPN.AcceptedPrivacyPolicyVersion != model.CurrentPrivacyPolicyID {
		t.Fatalf("expected the current version to be recorded, got %d", state.WhiteVPN.AcceptedPrivacyPolicyVersion)
	}
	if !privacyPolicyAccepted(state) {
		t.Fatal("the gate should be satisfied once the current version is accepted")
	}
}

// A policy that changes brings the gate back; that is the point of versioning it.
func TestPrivacyPolicyGateReturnsForANewerVersion(t *testing.T) {
	state := model.DefaultAppState()
	state.WhiteVPN.AcceptedPrivacyPolicyVersion = model.CurrentPrivacyPolicyID - 1
	if privacyPolicyAccepted(state) {
		t.Fatal("an older acceptance must not satisfy the current policy")
	}
	state.WhiteVPN.AcceptedPrivacyPolicyVersion = model.CurrentPrivacyPolicyID + 1
	if !privacyPolicyAccepted(state) {
		t.Fatal("a state ahead of this build should not be asked again")
	}
}

func TestSelectSubscriptionDefaultsToTheBuiltInCatalogue(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	if got := app.selectedSubscriptionID(); got != whiteDNSVPNSubscriptionID {
		t.Fatalf("expected the built-in catalogue by default, got %q", got)
	}

	if _, err := app.SelectSubscription("does-not-exist"); err == nil {
		t.Fatal("expected selecting a subscription that is not listed to be refused")
	}
	if got := app.selectedSubscriptionID(); got != whiteDNSVPNSubscriptionID {
		t.Fatalf("a refused selection must change nothing, got %q", got)
	}
}

func TestSelectSubscriptionClearsANodePickedInAnotherList(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	id := addTestSubscription(t, app, "Mine", "https://example.com/sub")

	app.mu.Lock()
	app.state.WhiteVPN.Connection.Node = "a node from the old list"
	app.state.WhiteVPN.CountryCode = "DE"
	_, _ = app.saveLocked()
	app.mu.Unlock()
	app.storeWhiteVPNNodes([]model.WhiteVPNNode{{Name: "cached"}}, testTime())

	state, err := app.SelectSubscription(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.SelectedSubscriptionID != id {
		t.Fatalf("expected the selection to be stored, got %q", state.SelectedSubscriptionID)
	}
	if state.WhiteVPN.Connection.Node != "" {
		t.Fatalf("a node named in the old list must not survive the change, got %q", state.WhiteVPN.Connection.Node)
	}
	if state.WhiteVPN.CountryCode != "DE" {
		t.Fatalf("a country filter is not tied to one list and should stay, got %q", state.WhiteVPN.CountryCode)
	}
	if nodes := app.whiteVPNNodesSnapshot(); len(nodes) != 0 {
		t.Fatalf("the cached catalogue belonged to the old subscription, got %#v", nodes)
	}
}

// A selection pointing at a subscription that has been deleted must not leave
// the app with no source of servers.
func TestDeletingTheSelectedSubscriptionFallsBackToTheCatalogue(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	id := addTestSubscription(t, app, "Mine", "https://example.com/sub")
	if _, err := app.SelectSubscription(id); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteV2RaySubscription(id); err != nil {
		t.Fatal(err)
	}
	if got := app.selectedSubscriptionID(); got != whiteDNSVPNSubscriptionID {
		t.Fatalf("expected the built-in catalogue to be selected again, got %q", got)
	}
}

func TestSubscriptionURLMustBeHTTPSUnlessItIsLoopback(t *testing.T) {
	for _, rawURL := range []string{"http://example.com/sub", "ftp://example.com/sub", "file:///tmp/sub"} {
		if _, err := validateV2RaySubscriptionURL(rawURL); err == nil {
			t.Fatalf("expected %q to be rejected", rawURL)
		}
	}
	for _, rawURL := range []string{"https://example.com/sub", "http://127.0.0.1:8080/sub", "http://localhost:8080/sub"} {
		if _, err := validateV2RaySubscriptionURL(rawURL); err != nil {
			t.Fatalf("expected %q to be accepted: %v", rawURL, err)
		}
	}
}

// The catalogue used to be stored as profiles so the Xray path could connect
// through one. Nothing fills that list now, so an older state file carries a
// frozen copy — and it was being counted and shown as though it were the
// catalogue, which is how the subscriptions page came to say 862 while the
// catalogue said 995.
func TestForgetBuiltInCatalogueProfilesKeepsWhatIsTheUsers(t *testing.T) {
	state := model.DefaultAppState()
	state.V2RayProfiles = []model.V2RayProfile{
		{ID: "stale-1", SubscriptionID: whiteDNSVPNSubscriptionID},
		{ID: "stale-2", SubscriptionID: whiteDNSVPNSubscriptionID},
		{ID: "mine", SubscriptionID: "user-1"},
		{ID: "hand-added"},
	}

	next := forgetBuiltInCatalogueProfiles(state)

	if len(next.V2RayProfiles) != 2 {
		t.Fatalf("expected the catalogue's copy to go and nothing else, got %#v", next.V2RayProfiles)
	}
	for _, profile := range next.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			t.Fatalf("a stale catalogue profile survived: %#v", profile)
		}
	}
}

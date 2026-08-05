package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/xray"
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

func TestPrepareWhiteDNSVPNConnectionImportsEncryptedSubscription(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	encrypted := encryptWhiteDNSVPNTestPayload(t, base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{
		testV2RaySubscriptionLink("one"),
		testV2RaySubscriptionLink("two"),
	}, "\n"))))

	state, err := app.prepareWhiteDNSVPNConnection(context.Background(), func(context.Context) (string, error) {
		return encrypted, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.V2RaySubscriptions) != 1 || state.V2RaySubscriptions[0].ID != whiteDNSVPNSubscriptionID {
		t.Fatalf("expected fixed WhiteDNS VPN subscription, got %#v", state.V2RaySubscriptions)
	}
	whiteDNSProfiles := whiteDNSVPNTestProfiles(state.V2RayProfiles)
	if len(whiteDNSProfiles) != 2 {
		t.Fatalf("expected two WhiteDNS VPN profiles, got %#v", state.V2RayProfiles)
	}
	if whiteDNSProfiles[0].Server != "one.example.com" || state.SelectedV2RayProfileID != whiteDNSProfiles[0].ID {
		t.Fatalf("expected first imported profile to be selected, got selected=%q profiles=%#v", state.SelectedV2RayProfileID, whiteDNSProfiles)
	}
	if state.V2RaySubscriptions[0].ImportedCount != 2 || state.V2RaySubscriptions[0].LastUpdatedAt == "" || state.V2RaySubscriptions[0].LastError != "" {
		t.Fatalf("unexpected subscription metadata: %#v", state.V2RaySubscriptions[0])
	}
}

func TestPrepareWhiteDNSVPNConnectionUsesCacheAfterRefreshFailure(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	encrypted := encryptWhiteDNSVPNTestPayload(t, base64.StdEncoding.EncodeToString([]byte(testV2RaySubscriptionLink("cached"))))
	if _, err := app.prepareWhiteDNSVPNConnection(context.Background(), func(context.Context) (string, error) {
		return encrypted, nil
	}); err != nil {
		t.Fatal(err)
	}

	app.mu.Lock()
	app.state.V2RaySubscriptions[0].LastUpdatedAt = time.Now().Add(-whiteDNSVPNSubscriptionRefreshInterval - time.Minute).UTC().Format(time.RFC3339)
	app.state.SelectedV2RayProfileID = ""
	app.mu.Unlock()

	state, err := app.prepareWhiteDNSVPNConnection(context.Background(), func(context.Context) (string, error) {
		return "", errors.New("network down")
	})
	if err != nil {
		t.Fatal(err)
	}
	whiteDNSProfiles := whiteDNSVPNTestProfiles(state.V2RayProfiles)
	if len(whiteDNSProfiles) != 1 || whiteDNSProfiles[0].Server != "cached.example.com" {
		t.Fatalf("expected cached profile to be preserved, got %#v", state.V2RayProfiles)
	}
	if state.SelectedV2RayProfileID != whiteDNSProfiles[0].ID {
		t.Fatalf("expected cached profile to be selected, got %q", state.SelectedV2RayProfileID)
	}
	if !strings.Contains(state.V2RaySubscriptions[0].LastError, "network down") {
		t.Fatalf("expected refresh error to be recorded, got %#v", state.V2RaySubscriptions[0])
	}
}

func TestPrepareWhiteDNSVPNConnectionSkipsFreshCache(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	encrypted := encryptWhiteDNSVPNTestPayload(t, base64.StdEncoding.EncodeToString([]byte(testV2RaySubscriptionLink("fresh"))))
	if _, err := app.prepareWhiteDNSVPNConnection(context.Background(), func(context.Context) (string, error) {
		return encrypted, nil
	}); err != nil {
		t.Fatal(err)
	}

	fetches := 0
	state, err := app.prepareWhiteDNSVPNConnection(context.Background(), func(context.Context) (string, error) {
		fetches++
		return "", errors.New("should not fetch")
	})
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 0 {
		t.Fatalf("expected fresh cache to skip fetch, got %d fetches", fetches)
	}
	whiteDNSProfiles := whiteDNSVPNTestProfiles(state.V2RayProfiles)
	if len(whiteDNSProfiles) != 1 || whiteDNSProfiles[0].Server != "fresh.example.com" {
		t.Fatalf("expected fresh cached profile, got %#v", state.V2RayProfiles)
	}
}

func TestPrepareWhiteDNSVPNConnectionSelectsBrowserReadyProfile(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	encrypted := encryptWhiteDNSVPNTestPayload(t, base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@172.65.111.43:22?security=none&type=tcp#tcp",
		testV2RaySubscriptionLink("browser"),
	}, "\n"))))

	state, err := app.prepareWhiteDNSVPNConnection(context.Background(), func(context.Context) (string, error) {
		return encrypted, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	selected := ""
	for _, profile := range state.V2RayProfiles {
		if profile.ID == state.SelectedV2RayProfileID {
			selected = profile.Server
		}
	}
	if selected != "browser.example.com" {
		t.Fatalf("expected browser-ready WhiteDNS profile to be selected, got %q", selected)
	}
}

func TestFrontedWhiteDNSVPNProfilePreservesHostSemantics(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.ID = "fronted"
	profile.Name = "Fronted"
	profile.SubscriptionID = whiteDNSVPNSubscriptionID
	profile.Protocol = model.V2RayProtocolVLESS
	profile.Server = "origin.example.com"
	profile.ServerPort = 443
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "ws"
	profile.TLS = true
	profile.TransportPath = "/ws"

	fronted, ok := frontedWhiteDNSVPNProfile(profile, "203.0.113.10")
	if !ok {
		t.Fatal("expected profile to be frontable")
	}
	if fronted.Server != "203.0.113.10" || fronted.TransportHost != "origin.example.com" || fronted.SNI != "" {
		t.Fatalf("unexpected fronted profile: %#v", fronted)
	}

	config, err := xray.RenderV2RayConfig(fronted, model.DefaultV2RaySettingsProfile())
	if err != nil {
		t.Fatal(err)
	}
	outbound := firstWhiteDNSVPNOutbound(t, config)
	settings := outbound["settings"].(map[string]any)
	if settings["address"] != "203.0.113.10" {
		t.Fatalf("expected fronting IP as outbound address, got %#v", settings)
	}
	stream := outbound["streamSettings"].(map[string]any)
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "origin.example.com" {
		t.Fatalf("expected original host as TLS serverName, got %#v", tlsSettings)
	}
	wsSettings := stream["wsSettings"].(map[string]any)
	if wsSettings["host"] != "origin.example.com" {
		t.Fatalf("expected original host as WS host, got %#v", wsSettings)
	}
}

func TestFrontedWhiteDNSVPNProfileKeepsExistingTransportHost(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Protocol = model.V2RayProtocolVLESS
	profile.Server = "origin.example.com"
	profile.ServerPort = 443
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "xhttp"
	profile.TLS = true
	profile.TransportHost = "cdn.example.com"

	fronted, ok := frontedWhiteDNSVPNProfile(profile, "203.0.113.10")
	if !ok {
		t.Fatal("expected profile to be frontable")
	}
	if fronted.TransportHost != "cdn.example.com" || fronted.SNI != "" {
		t.Fatalf("expected existing transport host to be kept, got %#v", fronted)
	}

	config, err := xray.RenderV2RayConfig(fronted, model.DefaultV2RaySettingsProfile())
	if err != nil {
		t.Fatal(err)
	}
	stream := firstWhiteDNSVPNOutbound(t, config)["streamSettings"].(map[string]any)
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "cdn.example.com" {
		t.Fatalf("expected existing transport host as TLS serverName, got %#v", tlsSettings)
	}
}

func TestFrontedWhiteDNSVPNProfileAllowsServerIPWithTransportHost(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Protocol = model.V2RayProtocolVLESS
	profile.Server = "108.162.192.75"
	profile.ServerPort = 443
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "ws"
	profile.TLS = true
	profile.TransportHost = "origin.example.com"

	fronted, ok := frontedWhiteDNSVPNProfile(profile, "203.0.113.10")
	if !ok {
		t.Fatal("expected CDN-IP profile with transport host to be frontable")
	}
	if fronted.Server != "203.0.113.10" || fronted.TransportHost != "origin.example.com" {
		t.Fatalf("unexpected fronted profile: %#v", fronted)
	}
}

func TestFrontedWhiteDNSVPNProfileRejectsUnsupportedProfiles(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Protocol = model.V2RayProtocolShadowsocks
	profile.Server = "origin.example.com"
	profile.ServerPort = 443
	profile.Password = "secret"
	profile.ShadowsocksMethod = "aes-128-gcm"

	if _, ok := frontedWhiteDNSVPNProfile(profile, "203.0.113.10"); ok {
		t.Fatal("expected unsupported profile to be rejected")
	}
	profile.Protocol = model.V2RayProtocolVLESS
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Server = "198.51.100.1"
	profile.TLS = true
	if _, ok := frontedWhiteDNSVPNProfile(profile, "203.0.113.10"); ok {
		t.Fatal("expected original IP profile to be rejected")
	}
}

func TestPrepareWhiteDNSVPNRuntimeProfileSelectsValidatedFrontingIP(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	profile := testWhiteDNSVPNFrontingProfile()
	app.state.V2RayProfiles = []model.V2RayProfile{profile}
	encrypted := encryptWhiteDNSVPNTestPayloadWithKey(t, "203.0.113.10\n198.51.100.20", whiteDNSVPNFrontingIPListKey)

	runtimeProfile, logs := app.prepareWhiteDNSVPNRuntimeProfile(
		context.Background(),
		profile,
		nil,
		func(context.Context) (string, error) { return encrypted, nil },
		func(_ context.Context, _ model.V2RayProfile, ips []string) []string {
			if len(ips) != 2 {
				t.Fatalf("expected parsed IPs, got %#v", ips)
			}
			return []string{"198.51.100.20", "203.0.113.10"}
		},
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			if candidate.Server == "203.0.113.10" {
				return model.V2RayPingResult{OK: true, Message: "ok"}
			}
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if runtimeProfile.Server != "203.0.113.10" {
		t.Fatalf("expected validated fronting IP, got %#v logs=%#v", runtimeProfile, logs)
	}
	if app.state.V2RayProfiles[0].Server != "origin.example.com" {
		t.Fatalf("stored profile was polluted with fronting IP: %#v", app.state.V2RayProfiles[0])
	}
}

func TestPrepareWhiteDNSVPNRuntimeProfileFallsBackWhenValidationFails(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	profile := testWhiteDNSVPNFrontingProfile()
	encrypted := encryptWhiteDNSVPNTestPayloadWithKey(t, "203.0.113.10", whiteDNSVPNFrontingIPListKey)

	runtimeProfile, logs := app.prepareWhiteDNSVPNRuntimeProfile(
		context.Background(),
		profile,
		nil,
		func(context.Context) (string, error) { return encrypted, nil },
		func(_ context.Context, _ model.V2RayProfile, _ []string) []string { return []string{"203.0.113.10"} },
		func(context.Context, model.V2RayProfile) model.V2RayPingResult {
			return model.V2RayPingResult{Message: "no route"}
		},
	)
	if runtimeProfile.Server != "origin.example.com" {
		t.Fatalf("expected original profile fallback, got %#v", runtimeProfile)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "using original server") {
		t.Fatalf("expected fallback log, got %#v", logs)
	}
}

func TestPrepareWhiteDNSVPNRuntimeProfileUsesCustomFrontingIPsInOrder(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	profile := testWhiteDNSVPNFrontingProfile()
	fetches := 0
	var tried []string

	runtimeProfile, logs := app.prepareWhiteDNSVPNRuntimeProfile(
		context.Background(),
		profile,
		[]string{"198.51.100.20", "203.0.113.10"},
		func(context.Context) (string, error) {
			fetches++
			return "", errors.New("should not fetch automatic IP list")
		},
		func(context.Context, model.V2RayProfile, []string) []string {
			t.Fatal("custom fronting IPs should not be ranked")
			return nil
		},
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.Server)
			if candidate.Server == "203.0.113.10" {
				return model.V2RayPingResult{OK: true, Message: "ok"}
			}
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if fetches != 0 {
		t.Fatalf("expected custom fronting to skip automatic fetch, got %d fetches", fetches)
	}
	if strings.Join(tried, ",") != "198.51.100.20,203.0.113.10" {
		t.Fatalf("expected custom IPs to be tried in order, got %#v", tried)
	}
	if runtimeProfile.Server != "203.0.113.10" {
		t.Fatalf("expected validated custom IP, got %#v logs=%#v", runtimeProfile, logs)
	}
}

func TestPrepareWhiteDNSVPNRuntimeProfileCustomFrontingFallsBackToOriginal(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	profile := testWhiteDNSVPNFrontingProfile()

	runtimeProfile, logs := app.prepareWhiteDNSVPNRuntimeProfile(
		context.Background(),
		profile,
		[]string{"203.0.113.10"},
		nil,
		nil,
		func(context.Context, model.V2RayProfile) model.V2RayPingResult {
			return model.V2RayPingResult{Message: "no route"}
		},
	)
	if runtimeProfile.Server != "origin.example.com" {
		t.Fatalf("expected original profile fallback, got %#v", runtimeProfile)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "custom validation failed") {
		t.Fatalf("expected custom fallback log, got %#v", logs)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionTriesCustomIPsAcrossProfiles(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	first := testWhiteDNSVPNProfile("white-one", "White One", "one.example.com")
	second := testWhiteDNSVPNProfile("white-two", "White Two", "two.example.com")
	app.state.V2RayProfiles = []model.V2RayProfile{first, second}

	var tried []string
	selection, err := app.prepareWhiteDNSVPNStartupSelection(
		context.Background(),
		[]string{"198.51.100.20", "203.0.113.10"},
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.Server+"|"+candidate.ID)
			if candidate.Server == "203.0.113.10" && candidate.ID == second.ID {
				return model.V2RayPingResult{OK: true, Message: "ok"}
			}
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, ",") != "198.51.100.20|white-one,198.51.100.20|white-two,203.0.113.10|white-one,203.0.113.10|white-two" {
		t.Fatalf("unexpected custom candidate order: %#v", tried)
	}
	if selection.storedProfile.ID != second.ID || selection.runtimeProfile.Server != "203.0.113.10" {
		t.Fatalf("unexpected selection: %#v", selection)
	}
	if app.state.V2RayProfiles[1].Server != "two.example.com" {
		t.Fatalf("stored profile was polluted: %#v", app.state.V2RayProfiles[1])
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionFallsBackToOriginalAfterCustomFails(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	first := testWhiteDNSVPNProfile("white-one", "White One", "one.example.com")
	second := testWhiteDNSVPNProfile("white-two", "White Two", "two.example.com")
	app.state.V2RayProfiles = []model.V2RayProfile{first, second}

	var tried []string
	selection, err := app.prepareWhiteDNSVPNStartupSelection(
		context.Background(),
		[]string{"203.0.113.10"},
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.Server+"|"+candidate.ID)
			if candidate.Server == second.Server {
				return model.V2RayPingResult{OK: true, Message: "ok"}
			}
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, ",") != "203.0.113.10|white-one,203.0.113.10|white-two,one.example.com|white-one,two.example.com|white-two" {
		t.Fatalf("unexpected fallback order: %#v", tried)
	}
	if selection.storedProfile.ID != second.ID || selection.runtimeProfile.Server != second.Server {
		t.Fatalf("expected original second profile fallback, got %#v", selection)
	}
	if !strings.Contains(strings.Join(selection.startupLogs, "\n"), "custom fronting failed; testing original profiles") {
		t.Fatalf("expected fallback log, got %#v", selection.startupLogs)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionStopsAfterFiveWorkingOriginalProfiles(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	app.state.V2RayProfiles = nil
	for i := 0; i < 7; i++ {
		app.state.V2RayProfiles = append(app.state.V2RayProfiles, testWhiteDNSVPNProfile(fmt.Sprintf("white-%d", i), fmt.Sprintf("White %d", i), fmt.Sprintf("origin-%d.example.com", i)))
	}

	var tried []string
	selection, err := app.prepareWhiteDNSVPNStartupSelection(
		context.Background(),
		nil,
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.ID)
			return model.V2RayPingResult{OK: true, Message: "ok"}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, ",") != "white-0,white-1,white-2,white-3,white-4" {
		t.Fatalf("expected five-profile sample, got %#v", tried)
	}
	if selection.storedProfile.ID != "white-0" || selection.runtimeProfile.Server != "origin-0.example.com" {
		t.Fatalf("expected first working profile, got %#v", selection)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionUsesFewerThanFiveWorkingOriginalProfiles(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	first := testWhiteDNSVPNProfile("white-one", "White One", "one.example.com")
	second := testWhiteDNSVPNProfile("white-two", "White Two", "two.example.com")
	third := testWhiteDNSVPNProfile("white-three", "White Three", "three.example.com")
	app.state.V2RayProfiles = []model.V2RayProfile{first, second, third}

	selection, err := app.prepareWhiteDNSVPNStartupSelection(
		context.Background(),
		nil,
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			if candidate.ID == second.ID {
				return model.V2RayPingResult{OK: true, Message: "ok"}
			}
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if selection.storedProfile.ID != second.ID {
		t.Fatalf("expected second profile, got %#v", selection)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionFallsBackFromBrowserReadyToAllProfiles(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	browserReady := testWhiteDNSVPNProfile("white-browser", "White Browser", "browser.example.com")
	fallback := testWhiteDNSVPNProfile("white-raw", "White Raw", "raw.example.com")
	fallback.TLS = false
	fallback.Network = "tcp"
	app.state.V2RayProfiles = []model.V2RayProfile{browserReady, fallback}

	var tried []string
	selection, err := app.prepareWhiteDNSVPNStartupSelection(
		context.Background(),
		nil,
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.ID)
			if candidate.ID == fallback.ID {
				return model.V2RayPingResult{OK: true, Message: "ok"}
			}
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, ",") != "white-browser,white-browser,white-raw" {
		t.Fatalf("expected browser-ready pass then all-profile fallback, got %#v", tried)
	}
	if selection.storedProfile.ID != fallback.ID {
		t.Fatalf("expected fallback profile, got %#v", selection)
	}
	if !strings.Contains(strings.Join(selection.startupLogs, "\n"), "browser-ready profiles failed") {
		t.Fatalf("expected browser-ready fallback log, got %#v", selection.startupLogs)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionExcludesActiveOriginalProfile(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	first := testWhiteDNSVPNProfile("white-one", "White One", "one.example.com")
	second := testWhiteDNSVPNProfile("white-two", "White Two", "two.example.com")
	app.state.V2RayProfiles = []model.V2RayProfile{first, second}

	var tried []string
	selection, err := app.prepareWhiteDNSVPNStartupSelectionExcluding(
		context.Background(),
		nil,
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.ID)
			return model.V2RayPingResult{OK: true, Message: "ok"}
		},
		whiteDNSVPNStartupExclusion{profileID: first.ID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, ",") != second.ID {
		t.Fatalf("expected active original profile to be skipped, got %#v", tried)
	}
	if selection.storedProfile.ID != second.ID {
		t.Fatalf("expected second profile, got %#v", selection)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionExcludesActiveFrontedPair(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	first := testWhiteDNSVPNProfile("white-one", "White One", "one.example.com")
	second := testWhiteDNSVPNProfile("white-two", "White Two", "two.example.com")
	app.state.V2RayProfiles = []model.V2RayProfile{first, second}

	var tried []string
	selection, err := app.prepareWhiteDNSVPNStartupSelectionExcluding(
		context.Background(),
		[]string{"198.51.100.20", "203.0.113.10"},
		func(_ context.Context, candidate model.V2RayProfile) model.V2RayPingResult {
			tried = append(tried, candidate.Server+"|"+candidate.ID)
			return model.V2RayPingResult{OK: true, Message: "ok"}
		},
		whiteDNSVPNStartupExclusion{profileID: first.ID, frontingIP: "198.51.100.20"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, ",") != "198.51.100.20|white-two" {
		t.Fatalf("expected active fronted pair to be skipped, got %#v", tried)
	}
	if selection.storedProfile.ID != second.ID || selection.runtimeProfile.Server != "198.51.100.20" {
		t.Fatalf("expected second profile on same IP, got %#v", selection)
	}
}

func TestPrepareWhiteDNSVPNStartupSelectionFailsWhenNoOriginalProfileWorks(t *testing.T) {
	app := testV2RaySubscriptionApp(t)
	app.state.V2RayProfiles = []model.V2RayProfile{
		testWhiteDNSVPNProfile("white-one", "White One", "one.example.com"),
		testWhiteDNSVPNProfile("white-two", "White Two", "two.example.com"),
	}

	_, err := app.prepareWhiteDNSVPNStartupSelection(
		context.Background(),
		nil,
		func(context.Context, model.V2RayProfile) model.V2RayPingResult {
			return model.V2RayPingResult{Message: "failed"}
		},
	)
	if err == nil || !strings.Contains(err.Error(), "no working subscription profile") {
		t.Fatalf("expected no-working error, got %v", err)
	}
}

func TestWhiteDNSVPNRuntimeFrontingIP(t *testing.T) {
	stored := testWhiteDNSVPNFrontingProfile()
	runtime := stored
	runtime.Server = "203.0.113.10"

	if got := whiteDNSVPNRuntimeFrontingIP(stored, runtime); got != "203.0.113.10" {
		t.Fatalf("expected runtime fronting IP, got %q", got)
	}
	runtime.Server = stored.Server
	if got := whiteDNSVPNRuntimeFrontingIP(stored, runtime); got != "" {
		t.Fatalf("expected no fronting IP when server is unchanged, got %q", got)
	}
	stored.SubscriptionID = "other"
	runtime.Server = "203.0.113.10"
	if got := whiteDNSVPNRuntimeFrontingIP(stored, runtime); got != "" {
		t.Fatalf("expected non-WhiteDNS profile to be ignored, got %q", got)
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

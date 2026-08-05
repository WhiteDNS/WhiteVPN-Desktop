package main

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

func TestExportV2RayProfileLinkIncludesWebSocketEarlyData(t *testing.T) {
	profile := duplicateTestV2RayProfile("v2ray-share", "Share")
	profile.Network = "ws"
	profile.TransportHost = "cdn.example.com"
	profile.TransportPath = "/ws"
	profile.WebSocketEarlyData = 2048
	profile.WebSocketEarlyDataHeader = "X-WS-ED"
	app := &App{}

	link, err := app.ExportV2RayProfileLink(profile)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("ed") != "2048" || query.Get("eh") != "X-WS-ED" {
		t.Fatalf("expected share link to include WebSocket early-data fields, got %q", link)
	}
}

func TestDeleteDuplicateV2RayProfilesKeepsSelectedProfile(t *testing.T) {
	state := model.DefaultAppState()
	first := duplicateTestV2RayProfile("v2ray-one", "First copy")
	selected := duplicateTestV2RayProfile("v2ray-selected", "Selected copy")
	unique := duplicateTestV2RayProfile("v2ray-unique", "Unique")
	unique.Server = "unique.example.com"
	state.V2RayProfiles = []model.V2RayProfile{model.DefaultV2RayProfile(), first, selected, unique}
	state.SelectedV2RayProfileID = selected.ID
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}

	result, err := app.DeleteDuplicateV2RayProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 1 {
		t.Fatalf("expected one duplicate removed, got %d", result.Removed)
	}
	if !containsV2RayProfile(result.State.V2RayProfiles, selected.ID) {
		t.Fatalf("selected duplicate should be kept: %#v", result.State.V2RayProfiles)
	}
	if containsV2RayProfile(result.State.V2RayProfiles, first.ID) {
		t.Fatalf("first duplicate should be removed when selected duplicate exists: %#v", result.State.V2RayProfiles)
	}
	if !containsV2RayProfile(result.State.V2RayProfiles, unique.ID) {
		t.Fatalf("unique profile should be kept: %#v", result.State.V2RayProfiles)
	}
	if result.State.SelectedV2RayProfileID != selected.ID {
		t.Fatalf("selected profile changed to %q", result.State.SelectedV2RayProfileID)
	}
}

func TestDeleteDuplicateV2RayProfilesIgnoresIncompleteProfiles(t *testing.T) {
	state := model.DefaultAppState()
	blankOne := model.V2RayProfile{ID: "blank-one", Name: "Blank one", Protocol: model.V2RayProtocolVLESS}
	blankTwo := model.V2RayProfile{ID: "blank-two", Name: "Blank two", Protocol: model.V2RayProtocolVLESS}
	state.V2RayProfiles = []model.V2RayProfile{model.DefaultV2RayProfile(), blankOne, blankTwo}
	app := &App{state: state}

	result, err := app.DeleteDuplicateV2RayProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 0 {
		t.Fatalf("expected incomplete profiles to be ignored, removed %d", result.Removed)
	}
}

func TestDeleteV2RayProfilesDeletesRequestedIDs(t *testing.T) {
	keep := duplicateTestV2RayProfile("v2ray-keep", "Keep")
	removeOne := duplicateTestV2RayProfile("v2ray-remove-one", "Remove one")
	removeTwo := duplicateTestV2RayProfile("v2ray-remove-two", "Remove two")
	state := model.DefaultAppState()
	state.V2RayProfiles = []model.V2RayProfile{keep, removeOne, removeTwo}
	state.SelectedV2RayProfileID = removeOne.ID
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: state,
	}

	next, err := app.DeleteV2RayProfiles([]string{removeOne.ID, removeTwo.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.V2RayProfiles) != 1 || next.V2RayProfiles[0].ID != keep.ID {
		t.Fatalf("expected only keep profile after bulk delete, got %#v", next.V2RayProfiles)
	}
	if next.SelectedV2RayProfileID != keep.ID {
		t.Fatalf("expected selected profile to move to remaining profile, got %q", next.SelectedV2RayProfileID)
	}
}

func TestV2RayProfilesByIDsLockedPreservesRequestedOrder(t *testing.T) {
	first := duplicateTestV2RayProfile("v2ray-first", "First")
	second := duplicateTestV2RayProfile("v2ray-second", "Second")
	third := duplicateTestV2RayProfile("v2ray-third", "Third")
	app := &App{
		state: model.AppState{
			V2RayProfiles: []model.V2RayProfile{first, second, third},
		},
	}

	got := app.v2rayProfilesByIDsLocked([]string{third.ID, "", "missing", first.ID, third.ID, second.ID})
	if len(got) != 3 {
		t.Fatalf("expected three known unique profiles, got %#v", got)
	}
	if got[0].ID != third.ID || got[1].ID != first.ID || got[2].ID != second.ID {
		t.Fatalf("expected requested profile order, got %#v", got)
	}
}

func TestV2RayPingResultJSONIncludesSpeedAndDelayFields(t *testing.T) {
	result := model.V2RayPingResult{
		ProfileID:              "v2ray-speed",
		Endpoint:               "proxy.example.com:443",
		OK:                     true,
		LatencyMs:              321,
		Message:                "ok",
		DownloadBytesPerSecond: 1_250_000,
		SpeedTestBytes:         500_000,
		SpeedTestDurationMs:    400,
		SpeedOK:                true,
		RealDelayMs:            222,
		DelayOK:                true,
		SpeedMessage:           "Speed 10.00 Mbps",
		DelayMessage:           "Real delay 222 ms",
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	expectedKeys := []string{
		"downloadBytesPerSecond",
		"speedTestBytes",
		"speedTestDurationMs",
		"speedOk",
		"realDelayMs",
		"delayOk",
		"speedMessage",
		"delayMessage",
	}
	for _, key := range expectedKeys {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("expected V2Ray test result JSON to include %q: %s", key, raw)
		}
	}
	if decoded["speedOk"] != true || decoded["delayOk"] != true {
		t.Fatalf("expected successful speed and delay flags, got %#v", decoded)
	}
}

func TestCancelV2RayProfileTestsCancelsActiveContext(t *testing.T) {
	app := &App{}
	ctx, done := app.beginV2RayProfileTestRun()
	defer done()

	if err := app.CancelV2RayProfileTests(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected active V2Ray profile test context to be cancelled")
	}
	app.v2rayTestMu.Lock()
	active := app.v2rayTestCancel != nil
	app.v2rayTestMu.Unlock()
	if active {
		t.Fatal("expected active V2Ray profile test cancel function to be cleared")
	}
}

func duplicateTestV2RayProfile(id string, name string) model.V2RayProfile {
	return model.V2RayProfile{
		ID:         id,
		Name:       name,
		Protocol:   model.V2RayProtocolVLESS,
		Server:     "proxy.example.com",
		ServerPort: 443,
		UUID:       "11111111-1111-1111-1111-111111111111",
		Network:    "tcp",
		TLS:        true,
	}
}

func containsV2RayProfile(items []model.V2RayProfile, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/session"
)

func publicAPITestApp(t *testing.T) *App {
	t.Helper()
	a := newSnapshotTestApp(t)
	a.store = profiles.NewStore(filepath.Join(a.configDir, "state.json"))
	a.state.V2RayProfiles = []model.V2RayProfile{manualProfile("manual-1", "Demo node", "localhost")}
	a.state.V2RayProfiles[0].Password = "profile-secret-marker"
	a.state.V2RaySubscriptions = []model.V2RaySubscription{{ID: "provider", Name: "Demo provider", URL: "https://provider.example/account-secret-marker?token=subscription-secret-marker"}}
	a.state.WhiteVPN.DNSPrivacy.DoHURL = "https://dns.example/dns-secret-marker"
	a.state.WhiteVPN.DNSPrivacy.Mode = model.DNSPrivacyDoH
	a.state.WhiteVPN.AcceptedPrivacyPolicyVersion = model.CurrentPrivacyPolicyID
	if _, err := a.saveLocked(); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPublicAPIStateAndEventsHideSecretsWhileEditorsAndPersistenceKeepThem(t *testing.T) {
	a := publicAPITestApp(t)
	state := a.GetAppState()
	if state.V2RayProfiles[0].UUID != "" || state.V2RayProfiles[0].Password != "" || state.V2RaySubscriptions[0].URL != "" || state.WhiteVPN.DNSPrivacy.DoHURL != "" {
		t.Fatal("Go public API returned private connection material")
	}
	if !state.V2RayProfiles[0].CredentialsReady || state.V2RaySubscriptions[0].DisplayURL != "https://provider.example" {
		t.Fatal("public metadata not usable")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-marker") {
		t.Fatal("public JSON leaks secrets")
	}
	p, err := a.ManualNodeProfile("manual-1")
	if err != nil || p.UUID == "" || p.Password != "profile-secret-marker" || p.PublicOnly {
		t.Fatal("explicit profile editor lost private material")
	}
	sub, err := a.GetV2RaySubscriptionForEdit("provider")
	if err != nil || sub.URL == "" || sub.PublicOnly {
		t.Fatal("explicit subscription editor lost URL")
	}
	settings := a.GetWhiteVPNSettingsForEdit()
	if settings.DNSPrivacy.DoHURL == "" || settings.PublicOnly {
		t.Fatal("explicit settings editor lost endpoint")
	}
	loaded, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.V2RayProfiles[0].UUID != p.UUID || loaded.V2RayProfiles[0].Password != p.Password || loaded.V2RaySubscriptions[0].URL != sub.URL {
		t.Fatal("public serialization contaminated persistence")
	}
	a.emitHook = func(name string, payload any) {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(string(encoded), "secret-marker") {
			t.Errorf("event %s exposes credentials", name)
		}
	}
	a.emit("state:changed", a.state)
	list, err := a.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	a.emit("nodes:changed", list)
	if len(list.Nodes) != 1 || list.Nodes[0].Link == "" {
		t.Fatal("internal node lost share link")
	}
	shared, err := a.ExportNodeLinks(model.ManualServerSourceID, []string{list.Nodes[0].Name})
	if err != nil || len(shared) != 1 || shared[0].Link != list.Nodes[0].Link {
		t.Fatal("explicit share cannot retrieve selected link")
	}
	if _, err := a.ExportNodeLinks("unknown-source", []string{list.Nodes[0].Name}); err == nil {
		t.Fatal("share silently selected another source")
	}
}

func TestPublicMetadataCannotOverwriteCredentialsAndPublicSettingsPreserveDNS(t *testing.T) {
	a := publicAPITestApp(t)
	public := a.GetAppState()
	if _, err := a.SaveV2RayProfile(public.V2RayProfiles[0]); err == nil {
		t.Fatal("profile metadata accepted as editor input")
	}
	if _, err := a.SaveManualNode(public.V2RayProfiles[0]); err == nil {
		t.Fatal("manual editor accepted metadata")
	}
	if _, err := a.SaveV2RaySubscription(public.V2RaySubscriptions[0]); err == nil {
		t.Fatal("subscription metadata accepted as editor input")
	}
	public.WhiteVPN.AllowLAN = !public.WhiteVPN.AllowLAN
	if _, err := a.SaveWhiteVPNSettings(public.WhiteVPN); err != nil {
		t.Fatal(err)
	}
	if a.GetWhiteVPNSettingsForEdit().DNSPrivacy.DoHURL != "https://dns.example/dns-secret-marker" {
		t.Fatal("a public settings toggle erased the private DNS endpoint")
	}
	if a.GetWhiteVPNSettings().DNSPrivacy.DoHURL != "" {
		t.Fatal("ordinary settings getter exposes custom endpoint")
	}
	p, _ := a.ManualNodeProfile("manual-1")
	if p.Password != "profile-secret-marker" {
		t.Fatal("rejected metadata wiped credentials")
	}
}

func TestPublicRestoreBlocksNetworkCacheAndFallbackUntilDetailsAreReentered(t *testing.T) {
	a := publicAPITestApp(t)
	a.state.SelectedSubscriptionID = "provider"
	if _, err := a.saveLocked(); err != nil {
		t.Fatal(err)
	}
	backup, err := a.ExportBackup()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(backup, "secret-marker") {
		t.Fatal("public backup exposes secrets")
	}
	if _, err := a.ImportBackup(backup); err != nil {
		t.Fatal(err)
	}
	fetches := 0
	a.fetchSubscriptionHook = func(context.Context, string) (string, error) { fetches++; return subscriptionLinks, nil }
	if _, err := a.StartWhiteDNSVPNConnection(); !errors.Is(err, model.ErrCredentialsRequired) {
		t.Fatal("restore attempted to start without credentials")
	}
	if _, _, err := a.subscriptionBodyWithFallback(context.Background()); !errors.Is(err, model.ErrCredentialsRequired) {
		t.Fatal("missing details chose a different subscription")
	}
	if _, _, err := a.resolveSubscriptionBody(context.Background(), "provider"); !errors.Is(err, model.ErrCredentialsRequired) {
		t.Fatal("missing details used network/cache")
	}
	if fetches != 0 {
		t.Fatal("unresolved restore fetched a source")
	}
	sub, err := a.GetV2RaySubscriptionForEdit("provider")
	if err != nil || !sub.CredentialRequired || sub.URL != "" {
		t.Fatal("unresolved subscription was removed")
	}
	sub.URL = "https://provider.example/reentered-secret-marker"
	if _, err := a.SaveV2RaySubscription(sub); err != nil {
		t.Fatal(err)
	}
	if err := a.sourceCredentialError("provider"); err != nil {
		t.Fatal("explicit URL repair remained blocked")
	}
	list, err := a.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 1 || !list.Nodes[0].CredentialRequired || list.Nodes[0].ProfileID != "manual-1" || list.Nodes[0].Link != "" {
		t.Fatal("restored manual profile is not visible for repair")
	}
	p, err := a.ManualNodeProfile("manual-1")
	if err != nil {
		t.Fatal(err)
	}
	p.UUID = "11111111-1111-1111-1111-111111111111"
	if _, err := a.SaveManualNode(p); err != nil {
		t.Fatal(err)
	}
	if err := a.sourceCredentialError(model.ManualServerSourceID); err != nil {
		t.Fatal("explicit manual repair remained blocked")
	}
}

func TestPublicStateConcurrentReadAndSaveIsAnIsolatedSnapshot(t *testing.T) {
	a := publicAPITestApp(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 24; i++ {
			s := a.GetAppState()
			backup, err := a.ExportBackup()
			if err != nil || strings.Contains(backup, "secret-marker") {
				t.Errorf("concurrent backup is not public: %v", err)
			}
			if _, err := json.Marshal(s); err != nil {
				t.Error(err)
			}
			if len(s.V2RayProfiles) > 0 {
				s.V2RayProfiles[0].Name = "caller mutation"
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 24; i++ {
			p, err := a.ManualNodeProfile("manual-1")
			if err != nil {
				t.Error(err)
				return
			}
			p.Name = "Changed by editor"
			if _, err := a.SaveV2RayProfile(p); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
	p, _ := a.ManualNodeProfile("manual-1")
	if p.Name == "caller mutation" || p.UUID == "" {
		t.Fatal("public snapshot mutated internal state")
	}
}

func TestPublicBackupRestoreRefusesAnOwnedSessionEvenWithDisconnectedStatus(t *testing.T) {
	a := publicAPITestApp(t)
	a.mihomo.swap(&session.Session{})
	defer a.mihomo.swap(nil)
	if _, err := a.ImportBackup(`{"schema":"whitedns.desktop.backup","version":2,"state":{}}`); err == nil {
		t.Fatal("owned session allowed restore")
	}
}

func TestPublicStringEventsHideTokenURLs(t *testing.T) {
	a := publicAPITestApp(t)
	var observed string
	a.emitHook = func(name string, payload any) {
		if name == "runtime:error" {
			observed, _ = payload.(string)
		}
	}
	a.emit("runtime:error", "request https://provider.example/event-secret-marker?token=private failed")
	if strings.Contains(observed, "event-secret-marker") || !strings.Contains(observed, "failed") {
		t.Fatal("string error event did not redact token URL")
	}
}

// Optional artifact for the browser smoke test, with disposable credentials only.
func TestPublicUIFixture(t *testing.T) {
	path := os.Getenv("WHITEVPN_PUBLIC_UI_FIXTURE_OUT")
	if path == "" {
		return
	}
	a := publicAPITestApp(t)
	a.state.SelectedSubscriptionID = model.ManualServerSourceID
	a.state.WhiteVPN.Language = "en"
	list, err := a.ListSubscriptionNodes(model.ManualServerSourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := a.ManualNodeProfile("manual-1")
	subscription, _ := a.GetV2RaySubscriptionForEdit("provider")
	fixture := map[string]any{"state": a.GetAppState(), "nodes": list, "profile": profile, "subscription": subscription, "settings": a.GetWhiteVPNSettingsForEdit()}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

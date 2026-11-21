//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/securestore"
)

func enablePrivateSnapshots(t *testing.T, a *App) {
	t.Helper()
	p, err := securestore.NewUserProtector("subscription-snapshots-v1")
	if err != nil {
		t.Fatal(err)
	}
	a.snapshotProtector = p
}

func TestProtectedSnapshotsMigrationPreservesOfflineCacheAndIgnoresOldWrites(t *testing.T) {
	a := newSnapshotTestApp(t)
	if err := a.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	legacyPath := a.subscriptionSnapshotPath("provider")
	enablePrivateSnapshots(t, a)
	if err := a.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plaintext snapshot retained")
	}
	stored, ok := a.lastKnownGoodSubscription("provider")
	if !ok || stored.Body != subscriptionLinks {
		t.Fatal("migration lost offline fallback")
	}
	raw, err := os.ReadFile(a.subscriptionSnapshotPath("provider"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(subscriptionLinks)) || bytes.Contains(raw, []byte(`"body"`)) {
		t.Fatal("plaintext cached credentials")
	}
	// A fresh app instance reads the same encrypted cache.
	b := &App{configDir: a.configDir, state: model.DefaultAppState()}
	enablePrivateSnapshots(t, b)
	if err := b.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if stored, ok := b.lastKnownGoodSubscription("provider"); !ok || stored.Body != subscriptionLinks {
		t.Fatal("restart lost encrypted cache")
	}
	// The legacy writer cannot replace the current body or restore a deleted one.
	old := &App{configDir: a.configDir}
	if err := old.storeSubscriptionSnapshot("provider", "old-body", 1); err != nil {
		t.Fatal(err)
	}
	if err := b.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if stored, ok := b.lastKnownGoodSubscription("provider"); !ok || stored.Body != subscriptionLinks {
		t.Fatal("old writer overwrote current cache")
	}
	b.forgetSubscriptionSnapshot("provider")
	if err := old.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	if err := b.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("deleted cache resurrected by old binary")
	}
}

func TestProtectedSnapshotTamperNeverFallsBackToLegacy(t *testing.T) {
	a := newSnapshotTestApp(t)
	if err := a.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	legacyPath := a.subscriptionSnapshotPath("provider")
	enablePrivateSnapshots(t, a)
	if err := a.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	path := a.subscriptionSnapshotPath("provider")
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(subscriptionSnapshot{SubscriptionID: "provider", Body: subscriptionLinks})
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("tampering fell back to legacy")
	}
	if err := a.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("migration served recreated legacy")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "tampered" {
		t.Fatal("tampered cache overwritten")
	}
}

func TestProtectedSnapshotInterruptedMigrationRetainsSource(t *testing.T) {
	a := newSnapshotTestApp(t)
	if err := a.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	legacyPath := a.subscriptionSnapshotPath("provider")
	enablePrivateSnapshots(t, a)
	path := a.subscriptionSnapshotPath("provider")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid-existing-vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.migrateSubscriptionSnapshots(); err == nil {
		t.Fatal("migration accepted corrupt destination")
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatal("source removed despite failed commit")
	}
	// Repair only this disposable test fixture; production never removes it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := a.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.lastKnownGoodSubscription("provider"); !ok {
		t.Fatal("retry lost source")
	}
}

func TestProtectedSnapshotInvalidMigrationMarkerBlocksImport(t *testing.T) {
	a := newSnapshotTestApp(t)
	if err := a.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	legacyPath := a.subscriptionSnapshotPath("provider")
	enablePrivateSnapshots(t, a)
	marker := securestore.New(filepath.Join(a.configDir, "state-v2", "subscription-migration.vault"), a.snapshotProtector)
	if err := marker.Write([]byte(`{"schema":"whitevpn.subscription-migration","version":999,"complete":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.migrateSubscriptionSnapshots(); !errors.Is(err, securestore.ErrCorrupt) {
		t.Fatal("unsupported marker allowed import")
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatal("blocked migration removed source")
	}
}

func TestProtectedSnapshotMigrationArchivesInterruptedPlaintextWrites(t *testing.T) {
	a := newSnapshotTestApp(t)
	if err := os.MkdirAll(a.subscriptionSnapshotDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := a.subscriptionSnapshotPath("provider") + ".123456.tmp"
	content := []byte("partial-subscription-credential-marker")
	if err := os.WriteFile(legacy, content, 0o600); err != nil {
		t.Fatal(err)
	}
	enablePrivateSnapshots(t, a)
	if err := a.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plaintext temporary remained")
	}
	archive := securestore.New(filepath.Join(a.subscriptionSnapshotDir(), "legacy-temporaries", filepath.Base(legacy)+".vault"), a.snapshotProtector)
	raw, err := archive.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if !bytes.Equal(raw, content) {
		t.Fatal("interrupted cache bytes lost")
	}
	if _, ok := a.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("interrupted body became active cache")
	}
}

func TestProtectedResetReinitializesVaultAndCannotResurrectCredentials(t *testing.T) {
	a := resetTestApp(t)
	if err := a.store.Save(a.state); err != nil {
		t.Fatal(err)
	}
	s, err := profiles.NewPlatformStore(filepath.Join(a.configDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.store = s
	a.state, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	enablePrivateSnapshots(t, a)
	if err := a.migrateSubscriptionSnapshots(); err != nil {
		t.Fatal(err)
	}
	if err := a.storeSubscriptionSnapshot("provider", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResetAppData(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.lastKnownGoodSubscription("provider"); ok {
		t.Fatal("cache survived reset")
	}
	if _, err := a.saveLocked(); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.V2RayProfiles) != 0 {
		t.Fatal("profiles resurrected after reset")
	}
	if _, err := os.Stat(filepath.Join(a.configDir, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reset wrote plaintext state")
	}
	raw, err := os.ReadFile(filepath.Join(a.configDir, "state-v2", "desktop-state.vault"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"v2rayProfiles"`) {
		t.Fatal("reset vault is plaintext")
	}
}

func TestWindowsAppStartupMigratesStateAndSnapshotsTogether(t *testing.T) {
	a := resetTestApp(t)
	if err := a.store.Save(a.state); err != nil {
		t.Fatal(err)
	}
	if err := a.storeSubscriptionSnapshot("user-1", subscriptionLinks, 2); err != nil {
		t.Fatal(err)
	}
	legacySnapshot := a.subscriptionSnapshotPath("user-1")
	started, err := newAppInConfigDir(a.configDir)
	if err != nil {
		t.Fatal(err)
	}
	if !started.store.IsProtected() || started.snapshotProtector == nil {
		t.Fatal("production startup skipped protection")
	}
	if len(started.state.V2RayProfiles) != 1 {
		t.Fatal("startup lost manual profiles")
	}
	if stored, ok := started.lastKnownGoodSubscription("user-1"); !ok || stored.Body != subscriptionLinks {
		t.Fatal("startup lost cache")
	}
	for _, legacy := range []string{legacySnapshot, filepath.Join(a.configDir, "state.json")} {
		if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("startup retained plaintext source")
		}
	}
	again, err := newAppInConfigDir(a.configDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.state.V2RayProfiles) != 1 {
		t.Fatal("second startup did not read encrypted state")
	}
	if again.legacyImport.Available {
		t.Fatal("existing encrypted install offered first-run import")
	}
}

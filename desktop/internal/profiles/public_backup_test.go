package profiles

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestPublicBackupRestoresPlaceholdersWithoutCredentialDefaults(t *testing.T) {
	source := newMigrationStore(t)
	if _, err := source.Load(); err != nil {
		t.Fatal(err)
	}
	state := credentialFixture()
	state.WhiteVPN.DNSPrivacy.Mode = model.DNSPrivacyDoH
	state.WhiteVPN.DNSPrivacy.DoHURL = "https://dns.example/DoH-credential-marker"
	state.SelectedSubscriptionID = "provider"
	if err := source.Save(state); err != nil {
		t.Fatal(err)
	}
	backup, err := source.ExportBackup(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(backup, "credential-marker") {
		t.Fatal("default backup contains credentials")
	}
	var document desktopBackup
	if err := json.Unmarshal([]byte(backup), &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != 2 {
		t.Fatal("public backup is not versioned independently of legacy v1")
	}
	target := newMigrationStore(t)
	if _, err := target.Load(); err != nil {
		t.Fatal(err)
	}
	restored, err := target.ImportBackup(backup)
	if err != nil {
		t.Fatal(err)
	}
	if restored.SelectedSubscriptionID != "provider" || len(restored.V2RaySubscriptions) != 1 || !restored.V2RaySubscriptions[0].CredentialRequired || restored.V2RaySubscriptions[0].URL != "" {
		t.Fatal("missing URL caused subscription deletion or selection fallback")
	}
	if !restored.V2RayProfiles[0].CredentialRequired || restored.V2RayProfiles[0].UUID != "" || IsExportableV2RayProfile(restored.V2RayProfiles[0]) {
		t.Fatal("missing credentials became exportable")
	}
	if _, err := ExportV2RayProfile(restored.V2RayProfiles[0]); !errors.Is(err, model.ErrCredentialsRequired) {
		t.Fatal("placeholder can produce a connection link")
	}
	for _, settings := range restored.SettingsProfiles {
		if settings.SOCKSPassword != "" || settings.SOCKSUsername != "" {
			t.Fatal("missing SOCKS auth replaced by defaults")
		}
	}
	if !restored.WhiteVPN.DNSPrivacy.CredentialRequired || restored.WhiteVPN.DNSPrivacy.DoHURL != "" {
		t.Fatal("omitted custom DNS was replaced by a service default")
	}
	reloaded, err := target.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.V2RaySubscriptions[0].CredentialRequired || reloaded.WhiteVPN.DNSPrivacy.DoHURL != "" {
		t.Fatal("restart lost the unresolved status")
	}
	assertPrivateFiles(t, target)
}

func TestPublicBackupCannotSupplyCredentialsOrChangePrivateSource(t *testing.T) {
	s := newMigrationStore(t)
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(credentialFixture()); err != nil {
		t.Fatal(err)
	}
	before, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	if _, err := s.ExportBackup(state); err != nil {
		t.Fatal(err)
	}
	after, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if string(before) != string(after) {
		t.Fatal("export changed private state")
	}
	malicious, err := json.Marshal(desktopBackup{Schema: desktopBackupSchema, Version: 2, State: privateAppState(credentialFixture())})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := s.ImportBackup(string(malicious))
	if err != nil {
		t.Fatal(err)
	}
	if restored.V2RayProfiles[0].UUID != "" || !restored.V2RayProfiles[0].CredentialRequired || restored.V2RaySubscriptions[0].URL != "" {
		t.Fatal("v2 backup bypassed secret omission policy")
	}
}

func TestPublicBackupFailureLeavesEncryptedStateAndManagedFilesUntouched(t *testing.T) {
	s := newMigrationStore(t)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	before, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	invalid := `{"schema":"whitedns.desktop.backup","version":2,"state":{"resolverProfiles":[{"id":"r","resolverSource":"file"}]}}`
	if _, err := s.ImportBackup(invalid); err == nil {
		t.Fatal("incomplete resolver backup accepted")
	}
	after, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if string(before) != string(after) {
		t.Fatal("invalid backup changed current state")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.path), "resolvers")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid restore created managed files")
	}
}

func TestPublicBackupRejectsMissingStateAndRollsBackUncommittedResolvers(t *testing.T) {
	for _, testCase := range []string{"missing-state", "null-state", "later-resolver-failure", "commit-failure"} {
		t.Run(testCase, func(t *testing.T) {
			s := newMigrationStore(t)
			if _, err := s.Load(); err != nil {
				t.Fatal(err)
			}
			before, err := s.protected.vault.Read()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			dir := s.resolverDirLocked()
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			existing := filepath.Join(dir, "r.txt")
			if err := os.WriteFile(existing, []byte("9.9.9.9:53\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			raw := `{"schema":"whitedns.desktop.backup","version":2}`
			switch testCase {
			case "null-state":
				raw = `{"schema":"whitedns.desktop.backup","version":2,"state":null}`
			case "later-resolver-failure", "commit-failure":
				raw = `{"schema":"whitedns.desktop.backup","version":2,"state":{"resolverProfiles":[{"id":"r","resolverSource":"file"},{"id":"later","resolverSource":"file"}]},"resolverFiles":[{"profileId":"r","resolverText":"1.1.1.1"}]}`
				if testCase == "commit-failure" {
					raw = `{"schema":"whitedns.desktop.backup","version":2,"state":{"resolverProfiles":[{"id":"r","resolverSource":"file"}]},"resolverFiles":[{"profileId":"r","resolverText":"1.1.1.1"}]}`
					s.protected.vault = &failingStateSnapshot{stateSnapshot: s.protected.vault, fail: true}
				}
			}
			if _, err := s.ImportBackup(raw); err == nil {
				t.Fatal("invalid or uncommittable backup accepted")
			}
			after, err := s.protected.vault.Read()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(after)
			if string(before) != string(after) {
				t.Fatal("failed restore changed committed state")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 1 || files[0].Name() != "r.txt" {
				t.Fatalf("uncommitted resolver files remain: %v, %v", files, err)
			}
			content, _ := os.ReadFile(existing)
			if string(content) != "9.9.9.9:53\n" {
				t.Fatal("failed restore overwrote existing resolver")
			}
		})
	}
}

func TestPublicBackupExportsOnlyValidatedResolverAddresses(t *testing.T) {
	s := newMigrationStore(t)
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "edited-resolvers.txt")
	if err := os.WriteFile(path, []byte("1.1.1.1\n# credential-marker\nhttps://bad.example/credential-marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state.ResolverProfiles = []model.ResolverProfile{{ID: "r", Name: "Edited file", ResolverSource: "file", ResolverFile: path}}
	raw, err := s.ExportBackup(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "credential-marker") || !strings.Contains(raw, "1.1.1.1") {
		t.Fatal("resolver backup retained arbitrary file contents")
	}
}

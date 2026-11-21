package profiles

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/securestore"
)

// Portable authenticated protector for migration/fault tests. Windows production
// DPAPI gets its own integration tests, rather than being replaced in production.
type migrationProtector struct{ cipher.AEAD }

func (p migrationProtector) Protect(raw []byte) ([]byte, error) {
	nonce := make([]byte, p.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return p.Seal(nonce, nonce, raw, nil), nil
}
func (p migrationProtector) Unprotect(raw []byte) ([]byte, error) {
	if len(raw) < p.NonceSize() {
		return nil, securestore.ErrCorrupt
	}
	return p.Open(nil, raw[:p.NonceSize()], raw[p.NonceSize():], nil)
}
func newMigrationStore(t *testing.T) *Store {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return newProtectedStore(filepath.Join(t.TempDir(), "state.json"), migrationProtector{aead})
}
func credentialFixture() model.AppState {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].EncryptionKey = "DNS-credential-marker"
	state.SettingsProfiles = append(state.SettingsProfiles, model.SettingsProfile{ID: "custom-settings", Name: "Custom", SOCKSUsername: "socks-user", SOCKSPassword: "SOCKS-credential-marker"})
	state.V2RayProfiles = []model.V2RayProfile{{ID: "manual", Name: "Manual", Protocol: "vless", Server: "localhost", ServerPort: 443, UUID: "UUID-credential-marker", Password: "password-credential-marker", HysteriaAuth: "hy-credential-marker", WireGuardSecretKey: "WG-credential-marker", WireGuardPreSharedKey: "PSK-credential-marker"}}
	state.V2RaySubscriptions = []model.V2RaySubscription{{ID: "provider", Name: "Provider", URL: "https://provider.example/path?token=URL-credential-marker"}}
	return state
}
func assertPrivateFiles(t *testing.T, s *Store) {
	t.Helper()
	if _, err := os.Stat(s.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy plaintext survived migration")
	}
	err := filepath.WalkDir(filepath.Dir(s.path), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), "credential-marker") {
			t.Fatalf("credential in file %s", filepath.Base(path))
		}
		if strings.HasSuffix(path, ".tmp") {
			t.Fatal("temporary snapshot remained")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProtectedMigrationPreservesCredentialsAndIgnoresDowngradeState(t *testing.T) {
	s := newMigrationStore(t)
	fixture := credentialFixture()
	if err := NewStore(s.path).Save(fixture); err != nil {
		t.Fatal(err)
	}
	expected, err := NewStore(s.path).Load()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, loaded) {
		t.Fatal("migration changed the legacy normalized state")
	}
	if loaded.ConnectionProfiles[0].EncryptionKey != fixture.ConnectionProfiles[0].EncryptionKey || loaded.V2RayProfiles[0].UUID != fixture.V2RayProfiles[0].UUID || loaded.V2RaySubscriptions[0].URL != fixture.V2RaySubscriptions[0].URL {
		t.Fatal("migration lost credentials")
	}
	if loaded.SettingsProfiles[1].SOCKSPassword != fixture.SettingsProfiles[1].SOCKSPassword || loaded.V2RayProfiles[0].WireGuardSecretKey != fixture.V2RayProfiles[0].WireGuardSecretKey {
		t.Fatal("migration lost secondary credentials")
	}
	assertPrivateFiles(t, s)
	checkpoint, err := s.protected.recovery.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(checkpoint)
	loaded.V2RayProfiles[0].Password = "new-credential-marker"
	if err := s.Save(loaded); err != nil {
		t.Fatal(err)
	}
	// Exercise the old store's actual serializer. This is not an old executable
	// acceptance test; it verifies isolation against that file format/write path.
	if err := NewStore(s.path).Save(model.DefaultAppState()); err != nil {
		t.Fatal(err)
	}
	again, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if again.V2RayProfiles[0].Password != "new-credential-marker" {
		t.Fatal("old state overwrote new vault")
	}
	after, err := s.protected.recovery.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(checkpoint, after) {
		t.Fatal("initial recovery checkpoint changed on edit")
	}
	assertPrivateFiles(t, s)
}

type failingStateSnapshot struct {
	stateSnapshot
	fail bool
}

func (s *failingStateSnapshot) Write(raw []byte) error {
	if s.fail {
		return errors.New("injected snapshot commit failure")
	}
	return s.stateSnapshot.Write(raw)
}

func TestProtectedMigrationCommitFailureLeavesSourceAndBlocksSave(t *testing.T) {
	s := newMigrationStore(t)
	if err := NewStore(s.path).Save(credentialFixture()); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(s.path)
	failure := &failingStateSnapshot{stateSnapshot: s.protected.vault, fail: true}
	s.protected.vault = failure
	if _, err := s.Load(); err == nil {
		t.Fatal("expected migration failure")
	}
	after, _ := os.ReadFile(s.path)
	if !bytes.Equal(original, after) {
		t.Fatal("source changed before commit")
	}
	if err := s.Save(model.DefaultAppState()); err == nil {
		t.Fatal("failed load allowed overwrite")
	}
	failure.fail = false
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	assertPrivateFiles(t, s)
}

func TestProtectedMigrationResumesAfterCheckpointFailure(t *testing.T) {
	s := newMigrationStore(t)
	if err := NewStore(s.path).Save(credentialFixture()); err != nil {
		t.Fatal(err)
	}
	failure := &failingStateSnapshot{stateSnapshot: s.protected.recovery, fail: true}
	s.protected.recovery = failure
	if _, err := s.Load(); err == nil {
		t.Fatal("expected checkpoint failure")
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatal("plaintext source removed before recovery verified")
	}
	if err := s.Save(model.DefaultAppState()); err == nil {
		t.Fatal("partial initialization allowed save")
	}
	// Simulate an old binary writing after interruption: committed new state wins.
	if err := NewStore(s.path).Save(model.DefaultAppState()); err != nil {
		t.Fatal(err)
	}
	failure.fail = false
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.V2RayProfiles[0].UUID != "UUID-credential-marker" {
		t.Fatal("resumed migration re-read old state")
	}
	assertPrivateFiles(t, s)
}

func TestProtectedStoreNeverFallsBackAfterCorruptionOrDeletion(t *testing.T) {
	for _, name := range []string{"corrupt", "missing", "future-version", "null-state"} {
		t.Run(name, func(t *testing.T) {
			s := newMigrationStore(t)
			if err := NewStore(s.path).Save(credentialFixture()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Load(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(s.path), "state-v2", "desktop-state.vault")
			switch name {
			case "corrupt":
				if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "future-version":
				if err := s.protected.vault.Write([]byte(`{"schema":"whitevpn.desktop.private-state","version":999,"state":{}}`)); err != nil {
					t.Fatal(err)
				}
			case "null-state":
				if err := s.protected.vault.Write([]byte(`{"schema":"whitevpn.desktop.private-state","version":1,"state":null}`)); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Save(model.DefaultAppState()); err == nil {
				t.Fatal("save replaced unavailable state")
			}
			if err := NewStore(s.path).Save(model.DefaultAppState()); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if _, err := s.Load(); err == nil {
				t.Fatal("load fell back to old state")
			}
			if err := s.Save(model.DefaultAppState()); err == nil {
				t.Fatal("failed load permitted save")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("unavailable vault overwritten")
			}
		})
	}
}

func TestProtectedStoreCorruptLegacyRemainsUnchanged(t *testing.T) {
	for _, raw := range []string{"{broken", "null", "[]", ""} {
		s := newMigrationStore(t)
		if err := os.WriteFile(s.path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(); err == nil {
			t.Fatal("bad legacy accepted")
		}
		after, _ := os.ReadFile(s.path)
		if string(after) != raw {
			t.Fatal("bad source changed")
		}
		if _, err := s.protected.vault.Read(); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("bad legacy committed")
		}
	}
}

func TestProtectedBackupImportCommitsCredentialsToVault(t *testing.T) {
	s := newMigrationStore(t)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	// Construct the original v1 artifact explicitly. The default exporter now
	// creates a public v2 backup and deliberately cannot supply credentials.
	encoded, err := json.Marshal(desktopBackup{Schema: desktopBackupSchema, Version: 1, State: privateAppState(credentialFixture())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportBackup(string(encoded)); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.V2RayProfiles[0].UUID != "UUID-credential-marker" {
		t.Fatal("legacy backup lost credentials")
	}
	assertPrivateFiles(t, s)
}

func TestProtectedStoreBlocksRecoveryCorruptionBeforeEditCommit(t *testing.T) {
	s := newMigrationStore(t)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	before, _ := s.protected.vault.Read()
	defer clear(before)
	if err := s.protected.recovery.Write([]byte(`{"schema":"unknown"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(credentialFixture()); err == nil {
		t.Fatal("edit accepted corrupt recovery")
	}
	after, _ := s.protected.vault.Read()
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("edit committed before recovery validation")
	}
}

func TestProtectedLoadFreshStateTracksFirstRunAndClearsRuntime(t *testing.T) {
	s := newMigrationStore(t)
	if exists, err := s.HasStoredState(); err != nil || exists {
		t.Fatal("fresh state detection failed")
	}
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := s.HasStoredState(); err != nil || !exists {
		t.Fatal("encrypted state counted as first run")
	}
	state.Runtime.Status = model.RuntimeConnected
	state.Runtime.Logs = []string{"runtime-secret"}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	raw, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var envelope privateStateEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.State.Runtime.Status != model.RuntimeDisconnected || strings.Contains(string(raw), "runtime-secret") {
		t.Fatal("runtime persisted")
	}
}

func TestProtectedMigrationArchivesInterruptedPlaintextStateWrites(t *testing.T) {
	s := newMigrationStore(t)
	if err := NewStore(s.path).Save(credentialFixture()); err != nil {
		t.Fatal(err)
	}
	interrupted := s.path + ".123456.tmp"
	content := []byte("{interrupted-state-credential-marker")
	if err := os.WriteFile(interrupted, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	assertPrivateFiles(t, s)
	archived := securestore.New(filepath.Join(filepath.Dir(s.path), "state-v2", "legacy-state-temporaries", filepath.Base(interrupted)+".vault"), s.protected.protector)
	raw, err := archived.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if !bytes.Equal(raw, content) {
		t.Fatal("temporary recovery lost original bytes")
	}
}

func TestProtectedEditCommitFailurePreservesPreviousState(t *testing.T) {
	s := newMigrationStore(t)
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	failure := &failingStateSnapshot{stateSnapshot: s.protected.vault, fail: true}
	s.protected.vault = failure
	state.ConnectionProfiles[0].EncryptionKey = "new-credential-marker"
	if err := s.Save(state); err == nil {
		t.Fatal("expected save failure")
	}
	after, err := s.protected.vault.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("failed save changed committed state")
	}
	failure.fail = false
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ConnectionProfiles[0].EncryptionKey == "new-credential-marker" {
		t.Fatal("failed edit became visible on reload")
	}
}

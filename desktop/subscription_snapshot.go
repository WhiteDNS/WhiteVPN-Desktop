package main

// The last subscription body that worked, kept where a restart can find it.
//
// Connecting fetched the subscription every time and had nowhere else to go
// when the fetch failed. For an app whose whole purpose is reaching a network
// that is being interfered with, that is the wrong way round: the provider being
// unreachable is the ordinary case, not the exceptional one, and it was enough
// to make a machine holding a perfectly good node list from ten minutes ago
// unable to connect at all.
//
// So a body that parsed is written down, and a fetch that fails falls back to
// it. Three things this is careful about, each of which was a way to lose the
// only good copy:
//
//   - Content is compiled before it is stored. A provider answering with an
//     error page, a captive portal, or half a document must not replace a
//     snapshot that works.
//   - Valid means it parses and yields at least one node. A timestamp cannot
//     make a broken document fresh, and a file that reads as zero nodes is not
//     a subscription with no servers — it is a file that is wrong.
//   - A stored snapshot that no longer parses is thrown away rather than
//     returned. Whatever corrupted it — a half-written file from a power cut, a
//     disk that lied — is not something to keep serving to the engine.
//
// This is deliberately not a cache in front of the network. A refresh still
// goes out and still reports what it finds. The snapshot is only consulted when
// the answer would otherwise be nothing at all.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/securestore"
)

// snapshotOrigin says where a body came from, which the caller needs in order
// to be honest about it: content served from a failed refresh must not be
// reported as freshly fetched.
type snapshotOrigin string

const (
	// originRefreshed is a body that was just fetched and parsed.
	originRefreshed snapshotOrigin = "refreshed"
	// originLastKnownGood is the stored body, returned because fetching failed.
	originLastKnownGood snapshotOrigin = "last-known-good"
)

// subscriptionSnapshot is one stored body and when it was fetched.
type subscriptionSnapshot struct {
	// SubscriptionID is written so a file found on its own can be identified,
	// and so a name collision between two hashes cannot serve one subscription's
	// nodes under another's.
	SubscriptionID string `json:"subscriptionId"`
	FetchedAt      string `json:"fetchedAt"`
	Body           string `json:"body"`
	// NodeCount is what the body held when it was stored. Kept for the log line
	// that tells a user how old the list they are looking at is and how big it
	// was, without having to parse the body to say so.
	NodeCount int `json:"nodeCount"`
}

func (a *App) subscriptionSnapshotDir() string {
	if a.snapshotProtector != nil {
		return filepath.Join(a.configDir, "state-v2", "subscriptions")
	}
	return filepath.Join(a.configDir, "subscriptions")
}

// subscriptionSnapshotPath names the file for a subscription.
//
// Hashed because a subscription id is a URL as often as it is a name, and a URL
// contains everything a filename may not. The id inside the file is what
// identifies it; this only has to be stable and unique.
func (a *App) subscriptionSnapshotPath(id string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(id)))
	ext := ".json"
	if a.snapshotProtector != nil {
		ext = ".vault"
	}
	return filepath.Join(a.subscriptionSnapshotDir(), hex.EncodeToString(sum[:16])+ext)
}

// storeSubscriptionSnapshot writes a body that has already been shown to parse.
//
// The caller compiles first and passes the count it got. Doing the parsing here
// would be the same work twice, and taking the caller's word for it is safe
// because the only caller is the one that just did it.
func (a *App) storeSubscriptionSnapshot(id string, body string, nodeCount int) error {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	if nodeCount <= 0 {
		// Refused rather than stored empty. A body that yields nothing is not a
		// subscription that has no servers today; it is a body that is wrong,
		// and storing it would overwrite the last one that was right.
		return fmt.Errorf("subscription snapshot: refusing to store a body with no nodes")
	}
	encoded, err := json.Marshal(subscriptionSnapshot{
		SubscriptionID: strings.TrimSpace(id),
		FetchedAt:      time.Now().UTC().Format(time.RFC3339),
		Body:           body,
		NodeCount:      nodeCount,
	})
	if err != nil {
		return err
	}
	defer clear(encoded)
	if a.snapshotProtector != nil {
		return securestore.New(a.subscriptionSnapshotPath(id), a.snapshotProtector).Write(encoded)
	}
	if err := os.MkdirAll(a.subscriptionSnapshotDir(), 0o755); err != nil {
		return err
	}
	// Written beside and renamed over, so a process that dies mid-write leaves
	// the previous snapshot whole rather than a truncated file that parses as
	// nothing.
	path := a.subscriptionSnapshotPath(id)
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// lastKnownGoodSubscription returns the stored body for a subscription, if there
// is one and it still holds nodes.
//
// A file that cannot be read, cannot be parsed, belongs to a different
// subscription, or no longer yields a node is removed. Keeping it would mean
// answering every failed fetch with something known to be useless, forever.
func (a *App) lastKnownGoodSubscription(id string) (subscriptionSnapshot, bool) {
	a.snapshotMu.Lock()
	discardReason := ""
	defer func() {
		a.snapshotMu.Unlock()
		// DeleteSubscription holds App.mu before taking snapshotMu. Logging only
		// after unlock avoids reversing that lock order on a malformed cache.
		if discardReason != "" {
			a.appendRuntimeLog(fmt.Sprintf("the saved subscription copy was discarded because %s — it will be fetched again", discardReason))
		}
	}()
	id = strings.TrimSpace(id)
	path := a.subscriptionSnapshotPath(id)
	var raw []byte
	var err error
	if a.snapshotProtector != nil {
		raw, err = securestore.New(path, a.snapshotProtector).Read()
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return subscriptionSnapshot{}, false
	}
	defer clear(raw)
	var snapshot subscriptionSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		_ = os.Remove(path)
		discardReason = "it could not be read"
		return subscriptionSnapshot{}, false
	}
	if strings.TrimSpace(snapshot.SubscriptionID) != id {
		_ = os.Remove(path)
		discardReason = "it belongs to a different subscription"
		return subscriptionSnapshot{}, false
	}
	// Checked against the body rather than trusted from the file. What was
	// written was valid; what is on disk now is a separate question, and this is
	// the one place that can tell the difference.
	nodes, err := whiteVPNNodesFromSubscription(snapshot.Body)
	if err != nil || len(nodes) == 0 {
		_ = os.Remove(path)
		discardReason = "it no longer holds any servers"
		return subscriptionSnapshot{}, false
	}
	snapshot.NodeCount = len(nodes)
	return snapshot, true
}

// forgetSubscriptionSnapshot removes a subscription's stored body, for a
// subscription the user deleted.
func (a *App) forgetSubscriptionSnapshot(id string) {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	_ = os.Remove(a.subscriptionSnapshotPath(id))
}

// Migrate all snapshots owned by this app, including caches for sources that
// are no longer selected. Commit/verify ciphertext before removing plaintext.
// An existing vault wins over files recreated by an older desktop binary.
func (a *App) migrateSubscriptionSnapshots() error {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	if a.snapshotProtector == nil {
		return securestore.ErrUnavailable
	}
	marker := securestore.New(filepath.Join(a.configDir, "state-v2", "subscription-migration.vault"), a.snapshotProtector)
	rawMarker, err := marker.Read()
	completed := false
	if err == nil {
		var checkpoint struct {
			Schema   string `json:"schema"`
			Version  int    `json:"version"`
			Complete bool   `json:"complete"`
		}
		decodeErr := json.Unmarshal(rawMarker, &checkpoint)
		clear(rawMarker)
		if decodeErr != nil || checkpoint.Schema != "whitevpn.subscription-migration" || checkpoint.Version != 1 || !checkpoint.Complete {
			return securestore.ErrCorrupt
		}
		completed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	legacyDir := filepath.Join(a.configDir, "subscriptions")
	entries, err := os.ReadDir(legacyDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		legacyBase := name
		temporary := false
		if base, ok := securestore.LegacyTemporaryBase(name); ok {
			legacyBase = base
			temporary = true
		}
		if filepath.Ext(legacyBase) != ".json" {
			continue
		}
		base := strings.TrimSuffix(legacyBase, ".json")
		decoded, err := hex.DecodeString(base)
		if err != nil || len(decoded) != 16 || base != strings.ToLower(base) {
			return fmt.Errorf("subscription snapshot migration: unrecognized legacy filename")
		}
		legacy := filepath.Join(legacyDir, name)
		info, err := os.Lstat(legacy)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("legacy subscription must be a regular file")
		}
		if temporary {
			destination := filepath.Join(a.subscriptionSnapshotDir(), "legacy-temporaries", name+".vault")
			if err := securestore.ArchiveLegacyFile(legacy, destination, a.snapshotProtector); err != nil {
				return err
			}
			continue
		}
		if completed {
			// An older binary's new cache must not resurrect a deleted snapshot or
			// replace a newer encrypted body after the one-time migration finished.
			if err := os.Remove(legacy); err != nil {
				return fmt.Errorf("legacy subscription cleanup failed")
			}
			continue
		}
		vault := securestore.New(filepath.Join(a.subscriptionSnapshotDir(), base+".vault"), a.snapshotProtector)
		stored, err := vault.Read()
		if errors.Is(err, os.ErrNotExist) {
			raw, readErr := readLegacySnapshotBounded(legacy)
			if readErr != nil {
				return readErr
			}
			err = vault.Write(raw)
			clear(raw)
		} else {
			clear(stored)
		}
		if err != nil {
			return fmt.Errorf("subscription snapshot migration could not commit: %w", err)
		}
		if err := os.Remove(legacy); err != nil {
			return fmt.Errorf("encrypted subscription committed but plaintext cleanup failed")
		}
	}
	if !completed {
		return marker.Write([]byte(`{"schema":"whitevpn.subscription-migration","version":1,"complete":true}`))
	}
	return nil
}

func readLegacySnapshotBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > securestore.MaxPlaintextBytes {
		return nil, fmt.Errorf("subscription migration requires a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, securestore.MaxPlaintextBytes+1))
	if len(raw) > securestore.MaxPlaintextBytes {
		clear(raw)
		return nil, fmt.Errorf("legacy subscription snapshot is too large")
	}
	return raw, err
}

// subscriptionIsStorable reports whether a subscription's body is worth keeping.
//
// The manual list is not: it is built out of the user's own stored configs every
// time it is asked for, so it cannot fail to be available and a second copy of
// it could only go stale.
func subscriptionIsStorable(id string) bool {
	id = strings.TrimSpace(id)
	// Manual configs are already in the state, and a merged list is derived
	// from the others rather than fetched — keeping a copy of either would
	// freeze something that can disagree with what it was made from, and the
	// sources it is built from each keep their own snapshot anyway.
	return id != model.ManualServerSourceID && !model.IsEverySubscription(id)
}

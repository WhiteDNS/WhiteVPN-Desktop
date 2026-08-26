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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitevpn-desktop/internal/model"
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
	return filepath.Join(a.configDir, "subscriptions")
}

// subscriptionSnapshotPath names the file for a subscription.
//
// Hashed because a subscription id is a URL as often as it is a name, and a URL
// contains everything a filename may not. The id inside the file is what
// identifies it; this only has to be stable and unique.
func (a *App) subscriptionSnapshotPath(id string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(id)))
	return filepath.Join(a.subscriptionSnapshotDir(), hex.EncodeToString(sum[:16])+".json")
}

// storeSubscriptionSnapshot writes a body that has already been shown to parse.
//
// The caller compiles first and passes the count it got. Doing the parsing here
// would be the same work twice, and taking the caller's word for it is safe
// because the only caller is the one that just did it.
func (a *App) storeSubscriptionSnapshot(id string, body string, nodeCount int) error {
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
	id = strings.TrimSpace(id)
	path := a.subscriptionSnapshotPath(id)
	raw, err := os.ReadFile(path)
	if err != nil {
		return subscriptionSnapshot{}, false
	}
	var snapshot subscriptionSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		a.discardSubscriptionSnapshot(id, "it could not be read")
		return subscriptionSnapshot{}, false
	}
	if strings.TrimSpace(snapshot.SubscriptionID) != id {
		a.discardSubscriptionSnapshot(id, "it belongs to a different subscription")
		return subscriptionSnapshot{}, false
	}
	// Checked against the body rather than trusted from the file. What was
	// written was valid; what is on disk now is a separate question, and this is
	// the one place that can tell the difference.
	nodes, err := whiteVPNNodesFromSubscription(snapshot.Body)
	if err != nil || len(nodes) == 0 {
		a.discardSubscriptionSnapshot(id, "it no longer holds any servers")
		return subscriptionSnapshot{}, false
	}
	snapshot.NodeCount = len(nodes)
	return snapshot, true
}

// discardSubscriptionSnapshot removes a stored body that turned out not to be
// usable, and says so where a user can see it.
func (a *App) discardSubscriptionSnapshot(id string, reason string) {
	_ = os.Remove(a.subscriptionSnapshotPath(id))
	a.appendRuntimeLog(fmt.Sprintf(
		"the saved copy of %q was discarded because %s — it will be fetched again", id, reason))
}

// forgetSubscriptionSnapshot removes a subscription's stored body, for a
// subscription the user deleted.
func (a *App) forgetSubscriptionSnapshot(id string) {
	_ = os.Remove(a.subscriptionSnapshotPath(id))
}

// subscriptionIsStorable reports whether a subscription's body is worth keeping.
//
// The manual list is not: it is built out of the user's own stored configs every
// time it is asked for, so it cannot fail to be available and a second copy of
// it could only go stale.
func subscriptionIsStorable(id string) bool {
	return strings.TrimSpace(id) != model.ManualServerSourceID
}

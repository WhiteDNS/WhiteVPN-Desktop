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
	"net"
	"slices"
	"strings"
	"time"
	"unicode"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	whiteDNSVPNSubscriptionID              = model.BuiltInSubscriptionID
	whiteVPNPrivateSubscriptionID          = model.PrivateBuiltInSubscriptionID
	whiteDNSVPNSubscriptionName            = "WhiteVPN Public"
	allSubscriptionsName                   = "All servers"
	whiteVPNPrivateSubscriptionName        = "WhiteVPN Private"
	whiteDNSVPNSubscriptionRefreshInterval = 3 * time.Hour

	whiteDNSVPNFrontingPingLimit       = 96
	whiteDNSVPNFrontingValidationLimit = 3
	whiteDNSVPNFrontingValidationTime  = 8 * time.Second
	whiteDNSVPNStartupWorkingSample    = 5
)

// Where the built-in catalogue comes from, and the key that opens it. Both are
// set at link time by the Makefile:
//
//	-X main.whiteDNSVPNSubscriptionURL=... -X main.whiteDNSVPNSubscriptionKey=...
//
// They used to be constants in this file, which is in a public repository, and
// had been since its first commit. That is not a weak secret — it is not a
// secret at all: anyone could read the key off a web page, fetch the encrypted
// catalogue and decrypt it, and what falls out is every node's address, UUID,
// password and REALITY keys. No binary needed, nothing to reverse engineer. A
// censor gets the complete list to block; anyone else gets the service for free.
//
// Moving them here does not make them secret either, and it must not be sold as
// though it does. They still travel inside every binary that ships, and a client
// that can decrypt the catalogue is a client an attacker can take apart. What it
// changes is the effort: reading a public file becomes pulling strings out of a
// 74 MB executable. That is worth doing, and it is the most that can be done
// while the client holds the key at all.
//
// The old values remain in this repository's history for ever, so this is only
// worth anything once the key on the server has been changed.
//
// A build made without them — `go build`, `wails build`, or anyone building from
// source — has no catalogue and says so. Manual configs and a user's own
// subscriptions are unaffected, which is the right shape for an open-source
// client of a managed service.
var (
	whiteDNSVPNSubscriptionURL     string
	whiteDNSVPNSubscriptionKey     string
	whiteVPNPrivateSubscriptionURL string
)

// The private catalogue's address.
//
// Written here rather than injected, unlike the public one above, and the
// difference is not an oversight. What the paragraphs above protect is the
// *key*: the public catalogue is AES-GCM ciphertext behind a Worker, so its
// address is only worth having with the passphrase that opens it. The private
// list is served in the clear from a public gist, which means its address is
// the whole of its protection — and an address that has to be readable by every
// copy of the app is not protection at all. Putting it in a build flag would
// dress up an unauthenticated public URL as a secret, which is worse than
// admitting what it is.
//
// If it is ever moved behind something that authenticates, this should move to
// a build flag with the other one. A var rather than a const so that a build can
// point at somewhere else without a patch:
//
//	-X main.whiteVPNPrivateSubscriptionURL=...

// builtInCatalogue is one of the two lists the app ships with.
type builtInCatalogue struct {
	id   string
	name string
	// url is where it is fetched from, empty when this build has none.
	url string
	// key decrypts it. Empty means the body is served in the clear, which is
	// what the private list does — not a missing key, an absent one.
	key string
}

// builtInCatalogues describes both, in the order they are listed.
func builtInCatalogues() []builtInCatalogue {
	return []builtInCatalogue{
		{
			id:   whiteVPNPrivateSubscriptionID,
			name: whiteVPNPrivateSubscriptionName,
			url:  strings.TrimSpace(whiteVPNPrivateSubscriptionURL),
		},
		{
			id:   whiteDNSVPNSubscriptionID,
			name: whiteDNSVPNSubscriptionName,
			url:  strings.TrimSpace(whiteDNSVPNSubscriptionURL),
			key:  strings.TrimSpace(whiteDNSVPNSubscriptionKey),
		},
	}
}

// builtInCatalogueFor finds one by id.
func builtInCatalogueFor(id string) (builtInCatalogue, bool) {
	for _, catalogue := range builtInCatalogues() {
		if catalogue.id == id {
			return catalogue, true
		}
	}
	return builtInCatalogue{}, false
}

// available reports whether this build can reach this catalogue at all.
//
// The public one needs both halves — an address with no key yields ciphertext
// nobody can read. The private one needs only an address, because there is
// nothing to open.
func (c builtInCatalogue) available() bool {
	if c.url == "" {
		return false
	}
	return c.id != whiteDNSVPNSubscriptionID || c.key != ""
}

// errNoBuiltInCatalogue is what a build without the catalogue credentials says
// when something asks for them.
var errNoBuiltInCatalogue = errors.New(
	"this build has no WhiteDNS catalogue: it was not built with one. Add a subscription of your own, or paste configs on the Servers page")

type whiteDNSVPNSubscriptionFetcher func(context.Context) (string, error)
type whiteDNSVPNFrontingIPFetcher func(context.Context) (string, error)
type whiteDNSVPNFrontingRanker func(context.Context, model.V2RayProfile, []string) []string
type whiteDNSVPNFrontingValidator func(context.Context, model.V2RayProfile) model.V2RayPingResult

type whiteDNSVPNEncryptedPayload struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Encoding   string `json:"encoding"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

type whiteDNSVPNRuntimeSelection struct {
	storedProfile  model.V2RayProfile
	runtimeProfile model.V2RayProfile
	startupLogs    []string
}

type whiteDNSVPNStartupExclusion struct {
	profileID  string
	frontingIP string
}

func fetchWhiteDNSVPNSubscriptionDocument(ctx context.Context, catalogue builtInCatalogue) (string, error) {
	if !catalogue.available() {
		return "", errNoBuiltInCatalogue
	}
	body, err := fetchV2RaySubscriptionDocument(ctx, catalogue.url)
	if err == nil {
		return body, nil
	}

	// The same fallback the user's own subscriptions get, and this path needs it
	// most: connecting is what fetches this, so there is never a tunnel to fall
	// back to here. A network that reads the ClientHello and cuts it leaves the
	// app with no node list, which is to say no app at all.
	if looksLikeInterference(err) {
		if fragmented := fragmentedDirectClient(false); fragmented != nil {
			if body, retryErr := fetchV2RaySubscriptionDocumentWith(ctx, catalogue.url, fragmented); retryErr == nil {
				return body, nil
			}
		}
	}
	return "", err
}

func (a *App) StartWhiteDNSVPNConnection() (model.AppState, error) {
	// The gate is enforced here and not only in the interface. A gate that only
	// the interface applies is one that is not really there.
	if state := a.GetAppState(); !privacyPolicyAccepted(state) {
		return state, fmt.Errorf("the privacy policy has not been accepted yet")
	}

	a.mu.Lock()
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.Status != model.RuntimeFailed {
		state := a.state
		a.mu.Unlock()
		return state, nil
	}
	a.mu.Unlock()

	return a.startWhiteDNSVPNWithMihomo()
}

// RefreshWhiteDNSVPNConnection reconnects. A session holds no stored profile to
// exclude and picks its node when it connects, so stopping and starting again is
// what refreshing means here.
func (a *App) RefreshWhiteDNSVPNConnection() (model.AppState, error) {
	if _, err := a.StopConnection(); err != nil {
		return a.GetAppState(), err
	}
	return a.StartWhiteDNSVPNConnection()
}

func (a *App) SaveWhiteDNSVPNFrontingIPs(rawText string) (model.AppState, error) {
	ips, err := parseWhiteDNSVPNCustomFrontingIPs(rawText)
	if err != nil {
		return a.GetAppState(), err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.WhiteDNSVPNFrontingIPs = ips
	return a.saveLocked()
}

// The subscription the app connects through.
//
// The built-in catalogue arrives encrypted from an address held in code; one the
// user added arrives as whatever they pointed at — share links, base64 of them,
// or a mihomo document — and session.PrepareConfig works out which. Both come
// through here so that the connect path and the connection dialog can never be
// looking at different lists.

// SelectSubscription chooses which server source the VPN connects through.
func (a *App) SelectSubscription(id string) (model.AppState, error) {
	id = strings.TrimSpace(id)
	a.mu.Lock()
	manualAvailable := id == model.ManualServerSourceID && slices.ContainsFunc(a.state.V2RayProfiles, func(profile model.V2RayProfile) bool {
		return profile.SubscriptionID == ""
	})
	// All is offered once there is more than one list to combine. With a single
	// list it would be that list under another name, which is a choice that
	// explains nothing.
	everyAvailable := model.IsEverySubscription(id) && len(a.state.V2RaySubscriptions) > 1
	if _, ok := findV2RaySubscription(a.state, id); !ok && !model.IsBuiltInSubscription(id) && !manualAvailable && !everyAvailable {
		state := a.state
		a.mu.Unlock()
		return state, fmt.Errorf("that server source is not in the list")
	}
	if a.state.SelectedSubscriptionID == id {
		state := a.state
		a.mu.Unlock()
		return state, nil
	}
	if a.mihomo.current() != nil {
		// The running tunnel was built from the current subscription's servers
		// and cannot be moved onto another's. Changing the setting under it
		// would leave the app naming one subscription while carrying traffic
		// through a different one.
		state := a.state
		a.mu.Unlock()
		return state, fmt.Errorf("disconnect before changing the subscription: the connection is running on the current one")
	}
	previous := strings.TrimSpace(a.state.SelectedSubscriptionID)
	if previous == "" {
		previous = whiteDNSVPNSubscriptionID
	}
	a.state.SelectedSubscriptionID = id
	a.state.WhiteVPN = model.SwapSubscriptionSelection(a.state.WhiteVPN, previous, id)
	state, err := a.saveLocked()
	a.mu.Unlock()

	return state, err
}

func (a *App) selectedSubscriptionID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := strings.TrimSpace(a.state.SelectedSubscriptionID)
	if id == "" {
		return whiteDNSVPNSubscriptionID
	}
	return id
}

// subscriptionBody fetches the selected subscription, ready for the engine.
func (a *App) subscriptionBody(ctx context.Context) (string, error) {
	return a.subscriptionBodyFor(ctx, a.selectedSubscriptionID())
}

// everySubscriptionBody is the "All" source: every list's servers, merged.
//
// Each source is read exactly as it would be on its own — same fetch, same
// snapshot fallback, same parser — and only then merged, so a list that is
// down behaves here the way it does anywhere else instead of taking the whole
// pool with it. A source that cannot be read is logged and skipped; the point
// of All is to have more to choose from, and refusing everything because one
// provider is unreachable would be the opposite.
//
// The merge is what stops two providers' "Germany 01" from being one name, and
// what stops a server both of them resell from being measured, listed and
// chosen as if it were two machines. See mihomoconf.MergeProxies.
func (a *App) everySubscriptionBody(ctx context.Context) (string, error) {
	sources := a.everySubscriptionSource()
	if len(sources) == 0 {
		return "", fmt.Errorf("there are no server lists to combine yet — add a subscription first")
	}

	merged := make([]mihomoconf.MergedSource, 0, len(sources))
	var failures int
	for _, source := range sources {
		body, err := a.subscriptionBodyFor(ctx, source.id)
		if err != nil {
			failures++
			a.appendRuntimeLog(fmt.Sprintf("combining every list: skipping %s: %v", source.name, err))
			continue
		}
		proxies, _, err := mihomoconf.ParseSubscription(body)
		if err != nil {
			failures++
			a.appendRuntimeLog(fmt.Sprintf("combining every list: %s held nothing usable: %v", source.name, err))
			continue
		}
		merged = append(merged, mihomoconf.MergedSource{Name: source.name, Proxies: proxies})
	}
	if len(merged) == 0 {
		return "", fmt.Errorf("none of the %d server lists could be read", len(sources))
	}

	document, err := mihomoconf.MergedDocument(mihomoconf.MergeProxies(merged))
	if err != nil {
		return "", err
	}
	if failures > 0 {
		a.appendRuntimeLog(fmt.Sprintf("combining every list: %d of %d lists contributed", len(merged), len(sources)))
	}
	return document, nil
}

type subscriptionSource struct {
	id   string
	name string
}

// everySubscriptionSource is every list All draws from, in the order they are
// merged — which is also the order that decides which copy of a duplicated
// server survives.
func (a *App) everySubscriptionSource() []subscriptionSource {
	a.mu.Lock()
	defer a.mu.Unlock()

	sources := make([]subscriptionSource, 0, len(a.state.V2RaySubscriptions)+1)
	for _, subscription := range a.state.V2RaySubscriptions {
		if model.IsBuiltInSubscription(subscription.ID) && !a.builtInCatalogueUsableLocked(subscription.ID) {
			continue
		}
		sources = append(sources, subscriptionSource{id: subscription.ID, name: subscription.Name})
	}
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == "" {
			sources = append(sources, subscriptionSource{id: model.ManualServerSourceID, name: "Saved configs"})
			break
		}
	}
	return sources
}

// builtInCatalogueUsableLocked reports whether this build can reach a catalogue
// at all, so a build without one does not spend a fetch failing.
func (a *App) builtInCatalogueUsableLocked(id string) bool {
	catalogue, known := builtInCatalogueFor(id)
	return known && catalogue.available()
}

// subscriptionBodyWithFallback is subscriptionBody, and the one place this app
// will connect through a list the user did not pick.
//
// A subscription that cannot be fetched otherwise means no VPN at all, on a
// machine where that is often the point. So when the chosen one cannot be had,
// every other source this app could connect through is tried in turn — the
// built-in catalogues first, private before public, then the user's own
// subscriptions in their own order, then anything pasted in by hand — and the
// first that yields a usable list is used, with a notice naming it.
//
// Two things it deliberately does not do.
//
// It does not change the stored selection. The user picked a list and still
// has it; the next attempt tries that one first again. A fallback that rewrites
// the choice is one that never gets reconsidered, and somebody whose provider
// was down for an hour would find themselves quietly moved for good.
//
// It does not fall back when the chosen list *was* fetched and simply had no
// node that carried traffic. That is what the watchdog is for, and treating it
// as an outage would move people off their own servers over a single bad node.
//
// It returns the subscription actually used, because everything downstream —
// the node cache, the hidden-node list — is keyed by subscription and would
// otherwise file one list's nodes under another's name.
func (a *App) subscriptionBodyWithFallback(ctx context.Context) (string, string, error) {
	selected := a.selectedSubscriptionID()
	body, err := a.subscriptionBodyFor(ctx, selected)
	if err == nil {
		return body, selected, nil
	}

	candidates := a.fallbackSubscriptionIDs(selected)
	if len(candidates) == 0 {
		return "", selected, err
	}
	// The reason the chosen list could not be used is worth keeping even when a
	// fallback works, or a service that is quietly always falling back looks
	// exactly like one that is quietly always fine.
	a.appendRuntimeLog(fmt.Sprintf("%s could not be reached (%v) — trying the other server lists",
		a.subscriptionDisplayName(selected), err))

	for _, candidate := range candidates {
		fallbackBody, fallbackErr := a.subscriptionBodyFor(ctx, candidate)
		if fallbackErr != nil {
			a.appendRuntimeLog(fmt.Sprintf("%s could not be reached either: %v",
				a.subscriptionDisplayName(candidate), fallbackErr))
			continue
		}
		a.emit("runtime:notice", fmt.Sprintf(
			"%s could not be reached, so this connection is going through %s instead. Your choice has not been changed — the next connection will try %s again.",
			a.subscriptionDisplayName(selected),
			a.subscriptionDisplayName(candidate),
			a.subscriptionDisplayName(selected)))
		return fallbackBody, candidate, nil
	}

	// Nothing worked. The error reported is the chosen list's: it is the one the
	// user asked for, and the others failing as well says nothing they can act
	// on beyond what the first said.
	return "", selected, err
}

// fallbackSubscriptionIDs is every other source this app could connect through,
// in the order they are worth trying.
//
// Built-in catalogues lead because they are the app's own and are there on every
// installation. Private before public within them, for the same reason the
// Subscriptions page lists it first. Then the user's own subscriptions, in the
// order they added them, and last the configs they pasted in by hand.
func (a *App) fallbackSubscriptionIDs(exclude string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	ids := make([]string, 0, len(a.state.V2RaySubscriptions)+len(model.BuiltInSubscriptionIDs))
	seen := map[string]bool{exclude: true}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}

	for _, catalogue := range builtInCatalogues() {
		// A build made without this one's address has nothing to fetch, and an
		// attempt would only spend the time it takes to fail.
		if catalogue.available() {
			add(catalogue.id)
		}
	}
	for _, subscription := range a.state.V2RaySubscriptions {
		if !model.IsBuiltInSubscription(subscription.ID) && strings.TrimSpace(subscription.URL) != "" {
			add(subscription.ID)
		}
	}
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == "" {
			add(model.ManualServerSourceID)
			break
		}
	}
	return ids
}

// subscriptionDisplayName is what a message about a subscription should call it.
func (a *App) subscriptionDisplayName(id string) string {
	if id == model.ManualServerSourceID {
		return "your saved configs"
	}
	a.mu.Lock()
	subscription, ok := findV2RaySubscription(a.state, id)
	a.mu.Unlock()
	if ok && strings.TrimSpace(subscription.Name) != "" {
		return subscription.Name
	}
	if catalogue, known := builtInCatalogueFor(id); known {
		return catalogue.name
	}
	return id
}

// subscriptionBodyFor fetches one by name, which is what lets the Servers page
// look at a subscription the VPN is not connecting through.
//
// A body that arrives and parses is stored; a fetch that fails falls back to the
// last one that did. See subscription_snapshot.go for why the fallback is worth
// having and what it refuses to store.
func (a *App) subscriptionBodyFor(ctx context.Context, id string) (string, error) {
	body, origin, err := a.resolveSubscriptionBody(ctx, id)
	if err != nil {
		return "", err
	}
	if origin == originLastKnownGood {
		// Said plainly rather than left to be inferred from a node list that
		// looks normal. Connecting on a list from yesterday is usually right and
		// occasionally why a node that no longer exists is being dialled.
		a.appendRuntimeLog(fmt.Sprintf(
			"%s could not be fetched — using the last copy that worked", id))
	}
	return body, nil
}

// resolveSubscriptionBody is subscriptionBodyFor, and where the body came from.
func (a *App) resolveSubscriptionBody(ctx context.Context, id string) (string, snapshotOrigin, error) {
	fetch := a.fetchSubscriptionBodyFor
	if a.fetchSubscriptionHook != nil {
		fetch = a.fetchSubscriptionHook
	}
	body, err := fetch(ctx, id)
	if !subscriptionIsStorable(id) {
		return body, originRefreshed, err
	}
	if err == nil {
		// Compiled before it is stored, so a captive portal's login page or a
		// half-served document cannot replace a snapshot that works. A body that
		// arrives and does not parse is a failed fetch by another name, and is
		// treated as one.
		if nodes, parseErr := whiteVPNNodesFromSubscription(body); parseErr == nil && len(nodes) > 0 {
			if storeErr := a.storeSubscriptionSnapshot(id, body, len(nodes)); storeErr != nil {
				// Not fatal. The body in hand is good and the connection can be
				// made from it; what failed is being able to make the next one
				// without the network.
				a.appendRuntimeLog(fmt.Sprintf("could not save a copy of %q: %v", id, storeErr))
			}
			return body, originRefreshed, nil
		} else if parseErr != nil {
			err = fmt.Errorf("subscription unreadable: %w", parseErr)
		} else {
			err = fmt.Errorf("subscription held no servers")
		}
	}
	if snapshot, ok := a.lastKnownGoodSubscription(id); ok {
		return snapshot.Body, originLastKnownGood, nil
	}
	return "", originRefreshed, err
}

// fetchSubscriptionBodyFor goes to wherever this subscription actually lives.
func (a *App) fetchSubscriptionBodyFor(ctx context.Context, id string) (string, error) {
	if model.IsEverySubscription(id) {
		return a.everySubscriptionBody(ctx)
	}
	if id == model.ManualServerSourceID {
		a.mu.Lock()
		manualProfiles := make([]model.V2RayProfile, 0, len(a.state.V2RayProfiles))
		for _, profile := range a.state.V2RayProfiles {
			if profile.SubscriptionID == "" {
				manualProfiles = append(manualProfiles, profile)
			}
		}
		a.mu.Unlock()
		body, err := profiles.ExportV2RayProfiles(manualProfiles)
		if err != nil {
			return "", fmt.Errorf("manual configs unavailable: %w", err)
		}
		return body, nil
	}
	if catalogue, ok := builtInCatalogueFor(id); ok {
		raw, err := fetchWhiteDNSVPNSubscriptionDocument(ctx, catalogue)
		if err != nil {
			return "", fmt.Errorf("subscription unavailable: %w", err)
		}
		// No key means the body is already what it says it is. Running the
		// decrypt over it would fail on the first field it could not find and
		// report the list as unreadable, which would be a true statement about
		// the wrong thing.
		if catalogue.key == "" {
			return raw, nil
		}
		body, err := decryptWhiteDNSVPNSubscription(raw, catalogue.key)
		if err != nil {
			return "", fmt.Errorf("subscription unreadable: %w", err)
		}
		return body, nil
	}

	a.mu.Lock()
	subscription, ok := findV2RaySubscription(a.state, id)
	a.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("the selected subscription is no longer in the list")
	}
	body, err := a.fetchSubscriptionDocument(ctx, subscription)
	if err != nil {
		return "", fmt.Errorf("subscription unavailable: %w", err)
	}
	return body, nil
}

func decryptWhiteDNSVPNSubscription(rawText string, passphrase string) (string, error) {
	return decryptWhiteDNSVPNPayload(rawText, passphrase, "subscription")
}

func decryptWhiteDNSVPNIPList(rawText string, passphrase string) (string, error) {
	return decryptWhiteDNSVPNPayload(rawText, passphrase, "IP list")
}

func decryptWhiteDNSVPNPayload(rawText string, passphrase string, label string) (string, error) {
	var payload whiteDNSVPNEncryptedPayload
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawText)), &payload); err != nil {
		return "", err
	}
	if payload.Version != 1 {
		return "", fmt.Errorf("unsupported WhiteDNS VPN %s version", label)
	}
	if payload.Algorithm != "AES-GCM" {
		return "", fmt.Errorf("unsupported WhiteDNS VPN %s algorithm", label)
	}
	if payload.Encoding != "base64url" {
		return "", fmt.Errorf("unsupported WhiteDNS VPN %s encoding", label)
	}
	iv, err := decodeWhiteDNSVPNBase64URL(payload.IV)
	if err != nil {
		return "", fmt.Errorf("invalid WhiteDNS VPN %s iv: %w", label, err)
	}
	ciphertext, err := decodeWhiteDNSVPNBase64URL(payload.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid WhiteDNS VPN %s ciphertext: %w", label, err)
	}
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt WhiteDNS VPN %s: %w", label, err)
	}
	return string(plaintext), nil
}

func parseWhiteDNSVPNFrontingIPs(rawText string) ([]string, error) {
	rawText = strings.TrimSpace(rawText)
	if rawText == "" {
		return nil, fmt.Errorf("WhiteDNS VPN fronting IP list is empty")
	}
	var values []string
	var decoded any
	if err := json.Unmarshal([]byte(rawText), &decoded); err == nil {
		collectWhiteDNSVPNIPStrings(decoded, &values)
	} else {
		values = strings.FieldsFunc(rawText, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
	}

	seen := map[string]struct{}{}
	ips := make([]string, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(strings.Trim(strings.TrimSpace(value), `"'`))
		if ip == nil || ip.To4() == nil {
			continue
		}
		normalized := ip.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		ips = append(ips, normalized)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("WhiteDNS VPN fronting IP list did not contain IPv4 addresses")
	}
	return ips, nil
}

func parseWhiteDNSVPNCustomFrontingIPs(rawText string) ([]string, error) {
	rawText = strings.TrimSpace(rawText)
	if rawText == "" {
		return []string{}, nil
	}
	seen := map[string]struct{}{}
	ips := make([]string, 0, profiles.MaxWhiteDNSVPNFrontingIPs)
	for _, part := range strings.Split(rawText, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.ContainsFunc(part, unicode.IsSpace) {
			return nil, fmt.Errorf("Fronting IPs must be comma-separated IPv4 addresses")
		}
		ip := net.ParseIP(part)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("Fronting IP must be a valid IPv4 address")
		}
		normalized := ip.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		ips = append(ips, normalized)
		if len(ips) > profiles.MaxWhiteDNSVPNFrontingIPs {
			return nil, fmt.Errorf("Fronting IP accepts up to %d IPv4 addresses", profiles.MaxWhiteDNSVPNFrontingIPs)
		}
	}
	return ips, nil
}

func collectWhiteDNSVPNIPStrings(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		*out = append(*out, typed)
	case []any:
		for _, item := range typed {
			collectWhiteDNSVPNIPStrings(item, out)
		}
	case map[string]any:
		for _, item := range typed {
			collectWhiteDNSVPNIPStrings(item, out)
		}
	}
}

func (a *App) whiteDNSVPNFrontingIPsSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return profiles.NormalizeWhiteDNSVPNFrontingIPs(a.state.WhiteDNSVPNFrontingIPs)
}

func whiteDNSVPNProfileHost(profile model.V2RayProfile) string {
	if host := strings.TrimSpace(profile.SNI); host != "" {
		return host
	}
	if host := firstWhiteDNSVPNHeaderHost(profile.TransportHost); host != "" {
		return host
	}
	return strings.TrimSpace(profile.Server)
}

func firstWhiteDNSVPNHeaderHost(value string) string {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return ""
}

func whiteDNSVPNHTTPFrontingTransport(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "ws", "websocket", "grpc", "httpupgrade", "xhttp", "splithttp", "http", "h2":
		return true
	default:
		return false
	}
}

func decodeWhiteDNSVPNBase64URL(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

// Keeping the built-in catalogues listed among the subscriptions.
//
// Their addresses are deliberately not stored. The app knows them itself and
// fetches from there, so leaving them out of the state means there is nowhere
// for them to be read from: not the subscriptions list, not a backup export,
// and not the state the interface is handed. A subscription the user adds is
// theirs and is stored and shown as they typed it.
// ensureBuiltInCataloguesLocked lists both of them, in their own order.
//
// Called wherever the list is read rather than only where it is written,
// because the private catalogue did not exist when most state files were
// written and its row has to appear in them too.
func (a *App) ensureBuiltInCataloguesLocked() {
	for _, catalogue := range builtInCatalogues() {
		a.ensureBuiltInSubscriptionLocked(catalogue.id)
	}
	a.ensureAllSubscriptionRowLocked()
}

// ensureAllSubscriptionRowLocked adds or removes the "All" row.
//
// It is a row rather than something the page draws for itself, because then
// selecting it, showing which is in use, and refusing to edit or delete it are
// the behaviour every other row already has.
//
// Offered once somebody has a list of their own and something to combine it
// with. Two conditions, and both earn their place.
//
// **At least one list they added.** This was asked for by people running
// several providers, and the built-in pair is not that: combining them would
// mix the private servers with the shared ones, which is the opposite of what
// choosing Private is for, and the fallback already covers one of them being
// down. A fresh install should have two rows, not three.
//
// **More than one list in total.** With a single list All would be that list
// under another name, which is a choice that explains nothing.
//
// It appears last, after the lists it is made of.
func (a *App) ensureAllSubscriptionRowLocked() {
	real, own := 0, 0
	for _, subscription := range a.state.V2RaySubscriptions {
		if model.IsEverySubscription(subscription.ID) {
			continue
		}
		real++
		if !model.IsBuiltInSubscription(subscription.ID) {
			own++
		}
	}
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == "" {
			own++
			real++
			break
		}
	}
	idx := findV2RaySubscriptionIndex(a.state.V2RaySubscriptions, model.AllSubscriptionsID)

	if real < 2 || own < 1 {
		if idx != -1 {
			a.state.V2RaySubscriptions = append(
				a.state.V2RaySubscriptions[:idx], a.state.V2RaySubscriptions[idx+1:]...)
			// Nothing to select any more, so the selection cannot stay on it.
			if model.IsEverySubscription(a.state.SelectedSubscriptionID) {
				a.state.SelectedSubscriptionID = model.DefaultAppState().SelectedSubscriptionID
			}
		}
		return
	}

	if idx == -1 {
		a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, model.V2RaySubscription{
			ID:   model.AllSubscriptionsID,
			Name: allSubscriptionsName,
		})
		return
	}
	a.state.V2RaySubscriptions[idx].Name = allSubscriptionsName
	a.state.V2RaySubscriptions[idx].URL = ""
}

func (a *App) ensureBuiltInSubscriptionLocked(id string) int {
	catalogue, known := builtInCatalogueFor(id)
	if !known {
		return -1
	}
	idx := findV2RaySubscriptionIndex(a.state.V2RaySubscriptions, catalogue.id)
	if idx == -1 {
		a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, model.V2RaySubscription{
			ID:   catalogue.id,
			Name: catalogue.name,
		})
		return len(a.state.V2RaySubscriptions) - 1
	}
	a.state.V2RaySubscriptions[idx].Name = catalogue.name
	// Clears it from a state file written before this was true.
	a.state.V2RaySubscriptions[idx].URL = ""
	return idx
}

// refreshWhiteDNSVPNCatalogue re-fetches the built-in catalogue on demand.
//
// The generic subscription refresh cannot do this one: it fetches whatever
// address is stored, and this one has none stored, arrives encrypted, and is
// counted in nodes rather than in stored profiles.
func (a *App) refreshBuiltInCatalogue(id string) (model.V2RaySubscriptionRefreshResult, error) {
	// Its own nodes, not the selected subscription's. Refresh is offered on
	// every row, so refreshing the one that is not selected has to fetch that
	// one rather than quietly re-reading whichever list the VPN page is on.
	list, err := a.ListSubscriptionNodes(id, true)
	if err != nil {
		a.mu.Lock()
		a.recordBuiltInSubscriptionErrorLocked(id, err)
		next, saveErr := a.saveLocked()
		a.mu.Unlock()
		return model.V2RaySubscriptionRefreshResult{
			State:        next,
			Subscription: findV2RaySubscriptionOrZero(next, id),
			Message:      err.Error(),
		}, saveErr
	}

	a.mu.Lock()
	idx := a.ensureBuiltInSubscriptionLocked(id)
	if idx == -1 {
		state := a.state
		a.mu.Unlock()
		return model.V2RaySubscriptionRefreshResult{State: state}, fmt.Errorf("unknown built-in catalogue %q", id)
	}
	a.state.V2RaySubscriptions[idx].ImportedCount = len(list.Nodes)
	a.state.V2RaySubscriptions[idx].LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	a.state.V2RaySubscriptions[idx].LastError = ""
	next, saveErr := a.saveLocked()
	a.mu.Unlock()

	return model.V2RaySubscriptionRefreshResult{
		State:        next,
		Subscription: findV2RaySubscriptionOrZero(next, id),
		OK:           true,
		Message:      fmt.Sprintf("%d nodes available.", len(list.Nodes)),
		Imported:     len(list.Nodes),
	}, saveErr
}

// forgetBuiltInCatalogueProfiles drops the stored copy of the catalogue.
//
// It used to be kept as V2RayProfiles so the Xray path could connect through
// one of them. Nothing fills it now and nothing reads it, so what is left in an
// older state file is a frozen list from whenever it was last written — and it
// was being counted and shown as though it were the catalogue. A subscription
// the user added keeps its profiles: those are theirs.
func forgetBuiltInCatalogueProfiles(state model.AppState) model.AppState {
	kept := make([]model.V2RayProfile, 0, len(state.V2RayProfiles))
	for _, profile := range state.V2RayProfiles {
		if model.IsBuiltInSubscription(profile.SubscriptionID) {
			continue
		}
		kept = append(kept, profile)
	}
	state.V2RayProfiles = kept
	return state
}

// forgetBuiltInSubscriptionURL strips the catalogue's address from a state that
// came from somewhere else — a file written by an older build, or a restored
// backup. Without it, hiding the address would only apply to states this build
// created.
func forgetBuiltInSubscriptionURL(state model.AppState) model.AppState {
	for idx := range state.V2RaySubscriptions {
		if model.IsBuiltInSubscription(state.V2RaySubscriptions[idx].ID) {
			state.V2RaySubscriptions[idx].URL = ""
		}
	}
	return state
}

func (a *App) recordWhiteDNSVPNSubscriptionErrorLocked(err error) {
	a.recordBuiltInSubscriptionErrorLocked(whiteDNSVPNSubscriptionID, err)
}

func (a *App) recordBuiltInSubscriptionErrorLocked(id string, err error) {
	if idx := a.ensureBuiltInSubscriptionLocked(id); idx != -1 {
		a.state.V2RaySubscriptions[idx].LastError = err.Error()
	}
}

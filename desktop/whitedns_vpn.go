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

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	whiteDNSVPNSubscriptionID              = model.BuiltInSubscriptionID
	whiteDNSVPNSubscriptionName            = "WhiteDNS VPN"
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
	whiteDNSVPNSubscriptionURL string
	whiteDNSVPNSubscriptionKey string
)

// errNoBuiltInCatalogue is what a build without the catalogue credentials says
// when something asks for them.
var errNoBuiltInCatalogue = errors.New(
	"this build has no WhiteDNS catalogue: it was not built with one. Add a subscription of your own, or paste configs on the Servers page")

// builtInCatalogueAvailable reports whether this build can reach the catalogue
// at all.
func builtInCatalogueAvailable() bool {
	return strings.TrimSpace(whiteDNSVPNSubscriptionURL) != "" &&
		strings.TrimSpace(whiteDNSVPNSubscriptionKey) != ""
}

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

func fetchWhiteDNSVPNSubscriptionDocument(ctx context.Context) (string, error) {
	if !builtInCatalogueAvailable() {
		return "", errNoBuiltInCatalogue
	}
	return fetchV2RaySubscriptionDocument(ctx, whiteDNSVPNSubscriptionURL)
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
	if _, ok := findV2RaySubscription(a.state, id); !ok && id != whiteDNSVPNSubscriptionID && !manualAvailable {
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
	a.state.SelectedSubscriptionID = id
	// The dashboard's node choice belongs to the subscription it was made in.
	a.state.WhiteVPN.Connection.Node = ""
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

// subscriptionBodyFor fetches one by name, which is what lets the Servers page
// look at a subscription the VPN is not connecting through.
func (a *App) subscriptionBodyFor(ctx context.Context, id string) (string, error) {
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
	if id == whiteDNSVPNSubscriptionID {
		raw, err := fetchWhiteDNSVPNSubscriptionDocument(ctx)
		if err != nil {
			return "", fmt.Errorf("subscription unavailable: %w", err)
		}
		body, err := decryptWhiteDNSVPNSubscription(raw, whiteDNSVPNSubscriptionKey)
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

// ensureWhiteDNSVPNSubscriptionLocked keeps the built-in catalogue listed among
// the subscriptions.
//
// Its address is deliberately not stored. The app knows it as a constant and
// fetches it from there, so leaving it out of the state means there is nowhere
// for it to be read from: not the subscriptions list, not a backup export, and
// not the state the interface is handed. A subscription the user adds is
// theirs and is stored and shown as they typed it.
func (a *App) ensureWhiteDNSVPNSubscriptionLocked() int {
	idx := findV2RaySubscriptionIndex(a.state.V2RaySubscriptions, whiteDNSVPNSubscriptionID)
	if idx == -1 {
		a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, model.V2RaySubscription{
			ID:   whiteDNSVPNSubscriptionID,
			Name: whiteDNSVPNSubscriptionName,
		})
		return len(a.state.V2RaySubscriptions) - 1
	}
	a.state.V2RaySubscriptions[idx].Name = whiteDNSVPNSubscriptionName
	// Clears it from a state file written before this was true.
	a.state.V2RaySubscriptions[idx].URL = ""
	return idx
}

// refreshWhiteDNSVPNCatalogue re-fetches the built-in catalogue on demand.
//
// The generic subscription refresh cannot do this one: it fetches whatever
// address is stored, and this one has none stored, arrives encrypted, and is
// counted in nodes rather than in stored profiles.
func (a *App) refreshWhiteDNSVPNCatalogue() (model.V2RaySubscriptionRefreshResult, error) {
	list, err := a.ListWhiteVPNNodes(true)
	if err != nil {
		a.mu.Lock()
		a.recordWhiteDNSVPNSubscriptionErrorLocked(err)
		next, saveErr := a.saveLocked()
		a.mu.Unlock()
		return model.V2RaySubscriptionRefreshResult{
			State:        next,
			Subscription: findV2RaySubscriptionOrZero(next, whiteDNSVPNSubscriptionID),
			Message:      err.Error(),
		}, saveErr
	}

	a.mu.Lock()
	idx := a.ensureWhiteDNSVPNSubscriptionLocked()
	a.state.V2RaySubscriptions[idx].ImportedCount = len(list.Nodes)
	a.state.V2RaySubscriptions[idx].LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	a.state.V2RaySubscriptions[idx].LastError = ""
	next, saveErr := a.saveLocked()
	a.mu.Unlock()

	return model.V2RaySubscriptionRefreshResult{
		State:        next,
		Subscription: findV2RaySubscriptionOrZero(next, whiteDNSVPNSubscriptionID),
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
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
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
		if state.V2RaySubscriptions[idx].ID == whiteDNSVPNSubscriptionID {
			state.V2RaySubscriptions[idx].URL = ""
		}
	}
	return state
}

func (a *App) recordWhiteDNSVPNSubscriptionErrorLocked(err error) {
	idx := a.ensureWhiteDNSVPNSubscriptionLocked()
	a.state.V2RaySubscriptions[idx].LastError = err.Error()
}

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	whiteDNSVPNSubscriptionID              = model.BuiltInSubscriptionID
	whiteDNSVPNSubscriptionName            = "WhiteDNS VPN"
	whiteDNSVPNSubscriptionURL             = "https://whitedns-sub.whitedns.workers.dev/encrypted"
	whiteDNSVPNSubscriptionKey             = "#2gzwj1##z%BVq*7M2sfxe6sV23ut1LQr87JagD4D#&"
	whiteDNSVPNSubscriptionRefreshInterval = 3 * time.Hour

	whiteDNSVPNFrontingIPListURL       = "https://whitedns-encrypted-ip-list.whitedns.workers.dev/v1/results/ips/encrypted"
	whiteDNSVPNFrontingIPListKey       = "kc*P$Hfw$YqRSf%Ypyfzx#F$kncPk9QG5%!W8M83K@f"
	whiteDNSVPNFrontingPingLimit       = 96
	whiteDNSVPNFrontingValidationLimit = 3
	whiteDNSVPNFrontingValidationTime  = 8 * time.Second
	whiteDNSVPNStartupWorkingSample    = 5
)

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
	return fetchV2RaySubscriptionDocument(ctx, whiteDNSVPNSubscriptionURL)
}

func fetchWhiteDNSVPNFrontingIPListDocument(ctx context.Context) (string, error) {
	return fetchV2RaySubscriptionDocument(ctx, whiteDNSVPNFrontingIPListURL)
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

func (a *App) prepareWhiteDNSVPNConnection(ctx context.Context, fetch whiteDNSVPNSubscriptionFetcher) (model.AppState, error) {
	if fetch == nil {
		fetch = fetchWhiteDNSVPNSubscriptionDocument
	}
	now := time.Now().UTC()

	a.mu.Lock()
	a.ensureWhiteDNSVPNSubscriptionLocked()
	if a.whiteDNSVPNCacheFreshLocked(now) {
		a.selectWhiteDNSVPNProfileLocked()
		next, err := a.saveLocked()
		a.mu.Unlock()
		return next, err
	}
	a.mu.Unlock()

	rawText, fetchErr := fetch(ctx)
	var imported []model.V2RayProfile
	var parseErr error
	if fetchErr == nil {
		var decrypted string
		decrypted, parseErr = decryptWhiteDNSVPNSubscription(rawText, whiteDNSVPNSubscriptionKey)
		if parseErr == nil {
			imported, parseErr = profiles.ParseV2RaySubscriptionDocument(decrypted)
		}
		if parseErr == nil && len(imported) == 0 {
			parseErr = fmt.Errorf("WhiteDNS VPN subscription did not contain profiles")
		}
	}
	refreshErr := fetchErr
	if refreshErr == nil {
		refreshErr = parseErr
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.ensureWhiteDNSVPNSubscriptionLocked()
	if refreshErr != nil {
		a.recordWhiteDNSVPNSubscriptionErrorLocked(refreshErr)
		if a.countWhiteDNSVPNProfilesLocked() > 0 {
			a.selectWhiteDNSVPNProfileLocked()
			return a.saveLocked()
		}
		next, saveErr := a.saveLocked()
		if saveErr != nil {
			return next, saveErr
		}
		return next, refreshErr
	}

	a.replaceWhiteDNSVPNProfilesLocked(imported, now)
	return a.saveLocked()
}

// The subscription the app connects through.
//
// The built-in catalogue arrives encrypted from an address held in code; one the
// user added arrives as whatever they pointed at — share links, base64 of them,
// or a mihomo document — and session.PrepareConfig works out which. Both come
// through here so that the connect path and the connection dialog can never be
// looking at different lists.

// SelectSubscription chooses which subscription the VPN connects through.
func (a *App) SelectSubscription(id string) (model.AppState, error) {
	id = strings.TrimSpace(id)
	a.mu.Lock()
	if _, ok := findV2RaySubscription(a.state, id); !ok && id != whiteDNSVPNSubscriptionID {
		state := a.state
		a.mu.Unlock()
		return state, fmt.Errorf("that subscription is not in the list")
	}
	if a.state.SelectedSubscriptionID == id {
		state := a.state
		a.mu.Unlock()
		return state, nil
	}
	a.state.SelectedSubscriptionID = id
	// The dashboard's node choice belongs to the subscription it was made in.
	a.state.WhiteVPN.Connection.Node = ""
	state, err := a.saveLocked()
	a.mu.Unlock()

	// The cached catalogue is the old subscription's.
	a.forgetWhiteVPNNodes()
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
	id := a.selectedSubscriptionID()
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
	body, err := fetchV2RaySubscriptionDocument(ctx, subscription.URL)
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

func (a *App) selectedWhiteDNSVPNProfileSnapshot() (model.V2RayProfile, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := profiles.NormalizeState(a.state)
	if profile, ok := selectedV2RayProfile(state); ok && profile.SubscriptionID == whiteDNSVPNSubscriptionID && whiteDNSVPNBrowserReadyProfile(profile) {
		return profiles.NormalizeV2RayProfile(profile), true
	}
	for _, profile := range state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID && whiteDNSVPNBrowserReadyProfile(profile) {
			return profiles.NormalizeV2RayProfile(profile), true
		}
	}
	for _, profile := range state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			return profiles.NormalizeV2RayProfile(profile), true
		}
	}
	return model.V2RayProfile{}, false
}

func (a *App) whiteDNSVPNProfileSnapshots() []model.V2RayProfile {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := profiles.NormalizeState(a.state)
	out := make([]model.V2RayProfile, 0, len(state.V2RayProfiles))
	for _, profile := range state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			out = append(out, profiles.NormalizeV2RayProfile(profile))
		}
	}
	return out
}

func (a *App) selectWhiteDNSVPNStoredProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, profile := range a.state.V2RayProfiles {
		if profile.ID == id && profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			a.state.SelectedV2RayProfileID = id
			return a.saveLocked()
		}
	}
	return a.state, fmt.Errorf("WhiteDNS VPN selected profile is missing")
}

func (a *App) whiteDNSVPNFrontingIPsSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return profiles.NormalizeWhiteDNSVPNFrontingIPs(a.state.WhiteDNSVPNFrontingIPs)
}

func whiteDNSVPNBrowserReadyProfile(profile model.V2RayProfile) bool {
	profile = profiles.NormalizeV2RayProfile(profile)
	switch profile.Protocol {
	case model.V2RayProtocolVLESS, model.V2RayProtocolVMess, model.V2RayProtocolTrojan:
	default:
		return false
	}
	return profile.TLS || whiteDNSVPNHTTPFrontingTransport(profile.Network)
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

func (a *App) whiteDNSVPNCacheFreshLocked(now time.Time) bool {
	if a.countWhiteDNSVPNProfilesLocked() == 0 {
		return false
	}
	idx := findV2RaySubscriptionIndex(a.state.V2RaySubscriptions, whiteDNSVPNSubscriptionID)
	if idx == -1 {
		return false
	}
	updatedAt, err := time.Parse(time.RFC3339, a.state.V2RaySubscriptions[idx].LastUpdatedAt)
	if err != nil {
		return false
	}
	age := now.Sub(updatedAt)
	return age >= 0 && age < whiteDNSVPNSubscriptionRefreshInterval
}

func (a *App) countWhiteDNSVPNProfilesLocked() int {
	count := 0
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			count++
		}
	}
	return count
}

func (a *App) selectWhiteDNSVPNProfileLocked() {
	for _, profile := range a.state.V2RayProfiles {
		if profile.ID == a.state.SelectedV2RayProfileID && profile.SubscriptionID == whiteDNSVPNSubscriptionID && whiteDNSVPNBrowserReadyProfile(profile) {
			return
		}
	}
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID && whiteDNSVPNBrowserReadyProfile(profile) {
			a.state.SelectedV2RayProfileID = profile.ID
			return
		}
	}
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			a.state.SelectedV2RayProfileID = profile.ID
			return
		}
	}
}

func (a *App) recordWhiteDNSVPNSubscriptionErrorLocked(err error) {
	idx := a.ensureWhiteDNSVPNSubscriptionLocked()
	a.state.V2RaySubscriptions[idx].LastError = err.Error()
}

func (a *App) replaceWhiteDNSVPNProfilesLocked(imported []model.V2RayProfile, now time.Time) {
	nextProfiles := make([]model.V2RayProfile, 0, len(a.state.V2RayProfiles)+len(imported))
	existingIDs := make(map[string]struct{}, len(a.state.V2RayProfiles)+len(imported))
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == whiteDNSVPNSubscriptionID {
			continue
		}
		nextProfiles = append(nextProfiles, profile)
		existingIDs[profile.ID] = struct{}{}
	}

	firstImportedID := ""
	firstPreferredID := ""
	baseID := now.UnixNano()
	for idx := range imported {
		profile := profiles.NormalizeV2RayProfile(imported[idx])
		profile.SubscriptionID = whiteDNSVPNSubscriptionID
		profile.ID = uniqueImportedV2RayID(existingIDs, baseID, idx)
		if firstImportedID == "" {
			firstImportedID = profile.ID
		}
		if firstPreferredID == "" && whiteDNSVPNBrowserReadyProfile(profile) {
			firstPreferredID = profile.ID
		}
		nextProfiles = append(nextProfiles, profile)
	}
	a.state.V2RayProfiles = nextProfiles
	if firstPreferredID != "" {
		a.state.SelectedV2RayProfileID = firstPreferredID
	} else if firstImportedID != "" {
		a.state.SelectedV2RayProfileID = firstImportedID
	}

	idx := a.ensureWhiteDNSVPNSubscriptionLocked()
	a.state.V2RaySubscriptions[idx].ImportedCount = len(imported)
	a.state.V2RaySubscriptions[idx].LastUpdatedAt = now.Format(time.RFC3339)
	a.state.V2RaySubscriptions[idx].LastError = ""
}

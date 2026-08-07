package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	v2rayPingTimeout     = 3500 * time.Millisecond
	v2rayPingParallelism = 64
	v2rayTestTimeout     = 18 * time.Second
	v2rayTestParallelism = 4

	v2raySubscriptionTimeout  = 10 * time.Second
	v2raySubscriptionMaxBytes = 2 << 20
)

func (a *App) SaveV2RayProfile(profile model.V2RayProfile) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	profile = profiles.NormalizeV2RayProfile(profile)
	if profile.ID == "" {
		profile.ID = fmt.Sprintf("v2ray-%d", time.Now().UnixMilli())
	}

	found := false
	for idx := range a.state.V2RayProfiles {
		if a.state.V2RayProfiles[idx].ID == profile.ID {
			a.state.V2RayProfiles[idx] = profile
			found = true
			break
		}
	}
	if !found {
		a.state.V2RayProfiles = append(a.state.V2RayProfiles, profile)
	}
	if !a.connectionSelectionLockedLocked() {
		a.state.SelectedV2RayProfileID = profile.ID
	}
	return a.saveLocked()
}

func (a *App) ImportV2RayProfiles(rawText string) (model.V2RayImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	imported, err := profiles.ParseV2RayProfileImports(rawText)
	if err != nil {
		return model.V2RayImportResult{State: a.state}, err
	}
	imported = slices.DeleteFunc(imported, func(profile model.V2RayProfile) bool {
		switch profile.Protocol {
		case model.V2RayProtocolVLESS,
			model.V2RayProtocolVMess,
			model.V2RayProtocolTrojan,
			model.V2RayProtocolShadowsocks,
			model.V2RayProtocolHysteria2,
			model.V2RayProtocolWireGuard:
			return false
		default:
			return true
		}
	})
	if len(imported) == 0 {
		return model.V2RayImportResult{State: a.state}, fmt.Errorf("no configs supported by the WhiteVPN engine found")
	}

	existingIDs := make(map[string]struct{}, len(a.state.V2RayProfiles)+len(imported))
	for _, profile := range a.state.V2RayProfiles {
		existingIDs[profile.ID] = struct{}{}
	}
	baseID := time.Now().UnixNano()
	for idx := range imported {
		imported[idx].ID = uniqueImportedV2RayID(existingIDs, baseID, idx)
	}
	a.state.V2RayProfiles = append(imported, a.state.V2RayProfiles...)
	a.forgetWhiteVPNNodes(model.ManualServerSourceID)
	if !a.connectionSelectionLockedLocked() {
		a.state.SelectedV2RayProfileID = imported[len(imported)-1].ID
	}

	next, err := a.saveLocked()
	return model.V2RayImportResult{State: next, Imported: len(imported)}, err
}

func (a *App) GetDefaultWhiteIPList() string {
	return profiles.DefaultWhiteIPList
}

func (a *App) GenerateV2RayWhiteIPProfiles(configText string, whiteIPText string) (model.V2RayWhiteIPGenerateResult, error) {
	converted, sourceProfileCount, whiteIPCount, err := profiles.ConvertV2RayProfilesToWhiteIPs(configText, whiteIPText)
	if err != nil {
		return model.V2RayWhiteIPGenerateResult{
			SourceProfileCount: sourceProfileCount,
			WhiteIPCount:       whiteIPCount,
		}, err
	}
	exportText, err := profiles.ExportV2RayProfiles(converted)
	if err != nil {
		return model.V2RayWhiteIPGenerateResult{
			Generated:          len(converted),
			SourceProfileCount: sourceProfileCount,
			WhiteIPCount:       whiteIPCount,
		}, err
	}
	return model.V2RayWhiteIPGenerateResult{
		ConfigText:         exportText,
		Generated:          len(converted),
		SourceProfileCount: sourceProfileCount,
		WhiteIPCount:       whiteIPCount,
	}, nil
}

func (a *App) ImportV2RayWhiteIPProfiles(configText string, whiteIPText string) (model.V2RayWhiteIPImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	imported, sourceProfileCount, whiteIPCount, err := profiles.ConvertV2RayProfilesToWhiteIPs(configText, whiteIPText)
	if err != nil {
		return model.V2RayWhiteIPImportResult{
			State:              a.state,
			SourceProfileCount: sourceProfileCount,
			WhiteIPCount:       whiteIPCount,
		}, err
	}

	existingIDs := make(map[string]struct{}, len(a.state.V2RayProfiles)+len(imported))
	for _, profile := range a.state.V2RayProfiles {
		existingIDs[profile.ID] = struct{}{}
	}
	baseID := time.Now().UnixNano()
	for idx := range imported {
		imported[idx].ID = uniqueImportedV2RayID(existingIDs, baseID, idx)
	}
	a.state.V2RayProfiles = append(imported, a.state.V2RayProfiles...)
	if !a.connectionSelectionLockedLocked() {
		a.state.SelectedV2RayProfileID = imported[len(imported)-1].ID
	}

	next, err := a.saveLocked()
	return model.V2RayWhiteIPImportResult{
		State:              next,
		Imported:           len(imported),
		SourceProfileCount: sourceProfileCount,
		WhiteIPCount:       whiteIPCount,
	}, err
}

func (a *App) SaveV2RaySubscription(subscription model.V2RaySubscription) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if strings.TrimSpace(subscription.ID) == whiteDNSVPNSubscriptionID {
		// The built-in catalogue is the app's, not the user's: its address is a
		// constant here and is deliberately not stored, so there is nothing for
		// an edit to change and saving one would only blank what it has.
		return a.state, fmt.Errorf("the built-in catalogue cannot be edited")
	}

	nameProvided := strings.TrimSpace(subscription.Name) != ""
	subscription = profiles.NormalizeV2RaySubscription(subscription)
	parsedURL, err := validateV2RaySubscriptionURL(subscription.URL)
	if err != nil {
		return a.state, err
	}
	if !nameProvided {
		subscription.Name = defaultV2RaySubscriptionName(parsedURL)
	}
	if subscription.ID == "" {
		subscription.ID = uniqueV2RaySubscriptionID(a.state.V2RaySubscriptions)
	}

	found := false
	for idx := range a.state.V2RaySubscriptions {
		if a.state.V2RaySubscriptions[idx].ID == subscription.ID {
			subscription.LastUpdatedAt = firstNonEmpty(subscription.LastUpdatedAt, a.state.V2RaySubscriptions[idx].LastUpdatedAt)
			subscription.LastError = firstNonEmpty(subscription.LastError, a.state.V2RaySubscriptions[idx].LastError)
			if subscription.ImportedCount == 0 {
				subscription.ImportedCount = a.state.V2RaySubscriptions[idx].ImportedCount
			}
			a.state.V2RaySubscriptions[idx] = subscription
			found = true
			break
		}
	}
	if !found {
		a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, subscription)
	}
	// The address may have changed under the same id, and the cached nodes were
	// parsed from the old one.
	a.forgetWhiteVPNNodes(subscription.ID)
	return a.saveLocked()
}

func (a *App) RefreshV2RaySubscription(id string) (model.V2RaySubscriptionRefreshResult, error) {
	id = strings.TrimSpace(id)
	if id == whiteDNSVPNSubscriptionID {
		// The catalogue is fetched from an address this app holds as a constant
		// and arrives encrypted, so neither the address nor the parsing below
		// applies to it.
		return a.refreshWhiteDNSVPNCatalogue()
	}
	a.mu.Lock()
	subscription, ok := findV2RaySubscription(a.state, id)
	if !ok {
		state := a.state
		a.mu.Unlock()
		return model.V2RaySubscriptionRefreshResult{State: state}, fmt.Errorf("V2Ray subscription not found")
	}
	if activeV2RaySubscriptionLocked(a.state, id) {
		state := a.state
		a.mu.Unlock()
		return model.V2RaySubscriptionRefreshResult{State: state, Subscription: subscription}, fmt.Errorf("active V2Ray subscription profile cannot be refreshed")
	}
	a.mu.Unlock()

	rawText, fetchErr := a.fetchSubscriptionDocument(context.Background(), subscription)
	var imported []model.V2RayProfile
	var importedCount int
	var parseErr error
	if fetchErr == nil {
		imported, parseErr = profiles.ParseV2RaySubscriptionDocument(rawText)
		importedCount = len(imported)
		if parseErr != nil {
			// Not share links. It may still be a whole mihomo configuration —
			// what a panel serves behind `?app=clash` — which is the engine's
			// own language and needs no conversion at all. There are no V2Ray
			// profiles to store for one, and nothing needs them: the node list,
			// the Servers page and the connect path all read the subscription
			// body itself.
			if nodes, err := whiteVPNNodesFromSubscription(rawText); err == nil {
				imported, parseErr, importedCount = nil, nil, len(nodes)
			}
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	idx := findV2RaySubscriptionIndex(a.state.V2RaySubscriptions, id)
	if idx == -1 {
		return model.V2RaySubscriptionRefreshResult{State: a.state}, fmt.Errorf("V2Ray subscription not found")
	}

	if fetchErr != nil || parseErr != nil {
		err := fetchErr
		if err == nil {
			err = parseErr
		}
		a.state.V2RaySubscriptions[idx].LastError = err.Error()
		next, saveErr := a.saveLocked()
		subscription = findV2RaySubscriptionOrZero(next, id)
		return model.V2RaySubscriptionRefreshResult{
			State:        next,
			Subscription: subscription,
			OK:           false,
			Message:      err.Error(),
		}, saveErr
	}

	nextProfiles := make([]model.V2RayProfile, 0, len(a.state.V2RayProfiles)+len(imported))
	existingIDs := make(map[string]struct{}, len(a.state.V2RayProfiles)+len(imported))
	removed := 0
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == id {
			removed++
			continue
		}
		nextProfiles = append(nextProfiles, profile)
		existingIDs[profile.ID] = struct{}{}
	}

	baseID := time.Now().UnixNano()
	for importedIdx := range imported {
		imported[importedIdx] = profiles.NormalizeV2RayProfile(imported[importedIdx])
		imported[importedIdx].SubscriptionID = id
		imported[importedIdx].ID = uniqueImportedV2RayID(existingIDs, baseID, importedIdx)
		nextProfiles = append(nextProfiles, imported[importedIdx])
	}
	a.state.V2RayProfiles = nextProfiles
	if !a.connectionSelectionLockedLocked() && len(imported) > 0 {
		a.state.SelectedV2RayProfileID = imported[len(imported)-1].ID
	}

	// A refresh is a request for the current list, cache included.
	a.forgetWhiteVPNNodes(id)
	a.state.V2RaySubscriptions[idx].ImportedCount = importedCount
	a.state.V2RaySubscriptions[idx].LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	a.state.V2RaySubscriptions[idx].LastError = ""
	next, err := a.saveLocked()
	subscription = findV2RaySubscriptionOrZero(next, id)
	return model.V2RaySubscriptionRefreshResult{
		State:        next,
		Subscription: subscription,
		OK:           true,
		Message:      fmt.Sprintf("Imported %d server%s.", importedCount, pluralSuffix(importedCount)),
		Imported:     importedCount,
		Removed:      removed,
	}, err
}

func (a *App) DeleteV2RaySubscription(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id = strings.TrimSpace(id)
	if id == "" {
		return a.state, nil
	}
	if id == whiteDNSVPNSubscriptionID {
		return a.state, fmt.Errorf("the built-in catalogue cannot be removed")
	}
	if activeV2RaySubscriptionLocked(a.state, id) {
		return a.state, fmt.Errorf("active V2Ray subscription cannot be deleted")
	}
	a.state.V2RaySubscriptions = slices.DeleteFunc(a.state.V2RaySubscriptions, func(subscription model.V2RaySubscription) bool {
		return subscription.ID == id
	})
	a.state.V2RayProfiles = slices.DeleteFunc(a.state.V2RayProfiles, func(profile model.V2RayProfile) bool {
		return profile.SubscriptionID == id
	})
	a.forgetWhiteVPNNodes(id)
	return a.saveLocked()
}

func (a *App) ExportV2RayProfileLink(profile model.V2RayProfile) (string, error) {
	return profiles.ExportV2RayProfile(profile)
}

func (a *App) ExportAllV2RayProfileLinks() (string, error) {
	a.mu.Lock()
	v2rayProfiles := append([]model.V2RayProfile(nil), a.state.V2RayProfiles...)
	a.mu.Unlock()
	return profiles.ExportV2RayProfiles(v2rayProfiles)
}

func (a *App) DeleteDuplicateV2RayProfiles() (model.V2RayDuplicateRemovalResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	remove := duplicateV2RayProfileIndexes(a.state.V2RayProfiles, a.state.SelectedV2RayProfileID, a.state.Runtime.ActiveConnectionID)
	if len(remove) == 0 {
		return model.V2RayDuplicateRemovalResult{State: a.state}, nil
	}

	nextProfiles := make([]model.V2RayProfile, 0, len(a.state.V2RayProfiles)-len(remove))
	for idx, profile := range a.state.V2RayProfiles {
		if !remove[idx] {
			nextProfiles = append(nextProfiles, profile)
		}
	}
	a.state.V2RayProfiles = nextProfiles
	next, err := a.saveLocked()
	return model.V2RayDuplicateRemovalResult{State: next, Removed: len(remove)}, err
}

func (a *App) DeleteV2RayProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Runtime.Status != model.RuntimeDisconnected && a.state.Runtime.ActiveConnectionID == id {
		return a.state, fmt.Errorf("active V2Ray profile cannot be deleted")
	}
	a.state.V2RayProfiles = slices.DeleteFunc(a.state.V2RayProfiles, func(profile model.V2RayProfile) bool {
		return profile.ID == id
	})
	return a.saveLocked()
}

func (a *App) DeleteV2RayProfiles(ids []string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	remove := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			remove[trimmed] = struct{}{}
		}
	}
	if len(remove) == 0 {
		return a.state, nil
	}
	if a.state.Runtime.Status != model.RuntimeDisconnected {
		if _, ok := remove[a.state.Runtime.ActiveConnectionID]; ok {
			return a.state, fmt.Errorf("active V2Ray profile cannot be deleted")
		}
	}
	a.state.V2RayProfiles = slices.DeleteFunc(a.state.V2RayProfiles, func(profile model.V2RayProfile) bool {
		_, ok := remove[profile.ID]
		return ok
	})
	return a.saveLocked()
}

func (a *App) SelectV2RayProfile(id string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !slices.ContainsFunc(a.state.V2RayProfiles, func(profile model.V2RayProfile) bool { return profile.ID == id }) {
		return a.state, fmt.Errorf("V2Ray profile not found")
	}
	if a.connectionSelectionLockedLocked() {
		return a.state, fmt.Errorf("V2Ray profile cannot be changed while connected")
	}
	a.state.SelectedV2RayProfileID = id
	return a.saveLocked()
}

func (a *App) ReorderV2RayProfiles(ids []string) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reordered, err := reorderProfiles(a.state.V2RayProfiles, ids, func(profile model.V2RayProfile) string {
		return profile.ID
	}, "V2Ray profile")
	if err != nil {
		return a.state, err
	}
	a.state.V2RayProfiles = reordered
	return a.saveLocked()
}

func (a *App) PingV2RayProfiles() ([]model.V2RayPingResult, error) {
	a.mu.Lock()
	profilesSnapshot := append([]model.V2RayProfile(nil), a.state.V2RayProfiles...)
	a.mu.Unlock()

	return pingV2RayProfilesSnapshot(profilesSnapshot), nil
}

func (a *App) PingV2RayProfileIDs(ids []string) ([]model.V2RayPingResult, error) {
	a.mu.Lock()
	profilesSnapshot := a.v2rayProfilesByIDsLocked(ids)
	a.mu.Unlock()

	return pingV2RayProfilesSnapshot(profilesSnapshot), nil
}

func pingV2RayProfilesSnapshot(profilesSnapshot []model.V2RayProfile) []model.V2RayPingResult {
	results := make([]model.V2RayPingResult, len(profilesSnapshot))
	workerCount := v2rayPingParallelism
	if len(profilesSnapshot) < workerCount {
		workerCount = len(profilesSnapshot)
	}
	if workerCount <= 0 {
		return results
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = pingV2RayProfile(profiles.NormalizeV2RayProfile(profilesSnapshot[idx]))
			}
		}()
	}
	for idx := range profilesSnapshot {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	return results
}

func (a *App) PingV2RayProfile(profile model.V2RayProfile) (model.V2RayPingResult, error) {
	return pingV2RayProfile(profiles.NormalizeV2RayProfile(profile)), nil
}

func (a *App) CancelV2RayProfileTests() error {
	a.cancelV2RayProfileTests()
	return nil
}

func (a *App) beginV2RayProfileTestRun() (context.Context, func()) {
	a.v2rayTestMu.Lock()
	if a.v2rayTestCancel != nil {
		a.v2rayTestCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.v2rayTestRunID++
	runID := a.v2rayTestRunID
	a.v2rayTestCancel = cancel
	a.v2rayTestMu.Unlock()

	var once sync.Once
	done := func() {
		once.Do(func() {
			a.v2rayTestMu.Lock()
			if a.v2rayTestRunID == runID {
				a.v2rayTestCancel = nil
			}
			a.v2rayTestMu.Unlock()
			cancel()
		})
	}
	return ctx, done
}

func (a *App) cancelV2RayProfileTests() {
	a.v2rayTestMu.Lock()
	cancel := a.v2rayTestCancel
	a.v2rayTestCancel = nil
	a.v2rayTestMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *App) testV2RayProfilesSnapshot(
	ctx context.Context,
	profilesSnapshot []model.V2RayProfile,
	test func(context.Context, model.V2RayProfile) model.V2RayPingResult,
) []model.V2RayPingResult {
	results := make([]model.V2RayPingResult, 0, len(profilesSnapshot))
	workerCount := v2rayTestParallelism
	if len(profilesSnapshot) < workerCount {
		workerCount = len(profilesSnapshot)
	}
	if workerCount <= 0 {
		return results
	}
	jobs := make(chan model.V2RayProfile)
	var resultsMu sync.Mutex
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case profile, ok := <-jobs:
					if !ok {
						return
					}
					profileCtx, cancel := context.WithTimeout(ctx, v2rayTestTimeout)
					result := test(profileCtx, profiles.NormalizeV2RayProfile(profile))
					cancel()
					if result.ProfileID == "" || (ctx.Err() != nil && !result.OK && !result.SpeedOK && !result.DelayOK) {
						continue
					}
					resultsMu.Lock()
					results = append(results, result)
					resultsMu.Unlock()
				}
			}
		}()
	}
sendJobs:
	for _, profile := range profilesSnapshot {
		select {
		case <-ctx.Done():
			break sendJobs
		case jobs <- profile:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func (a *App) v2rayProfilesByIDsLocked(ids []string) []model.V2RayProfile {
	if len(ids) == 0 {
		return nil
	}
	byID := make(map[string]model.V2RayProfile, len(a.state.V2RayProfiles))
	for _, profile := range a.state.V2RayProfiles {
		byID[profile.ID] = profile
	}
	seen := make(map[string]struct{}, len(ids))
	profilesSnapshot := make([]model.V2RayProfile, 0, len(ids))
	for _, rawID := range ids {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		profile, ok := byID[id]
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		profilesSnapshot = append(profilesSnapshot, profile)
	}
	return profilesSnapshot
}

func pingV2RayProfile(profile model.V2RayProfile) model.V2RayPingResult {
	server := strings.TrimSpace(profile.Server)
	result := model.V2RayPingResult{
		ProfileID: profile.ID,
		Endpoint:  server,
	}
	if server == "" {
		result.Message = "Server is required"
		return result
	}
	if profile.ServerPort <= 0 || profile.ServerPort > 65535 {
		result.Message = "Valid server port is required"
		return result
	}

	address := net.JoinHostPort(server, strconv.Itoa(profile.ServerPort))
	result.Endpoint = address
	ctx, cancel := context.WithTimeout(context.Background(), v2rayPingTimeout)
	defer cancel()

	dialer := net.Dialer{Timeout: v2rayPingTimeout}
	started := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	latency := time.Since(started).Milliseconds()
	result.LatencyMs = latency
	if err != nil {
		result.Message = fmt.Sprintf("%s unavailable: %v", address, err)
		return result
	}
	_ = conn.Close()

	result.OK = true
	result.Message = fmt.Sprintf("%s reachable in %d ms", address, latency)
	return result
}

func newV2RayRuntimeTestResult(profile model.V2RayProfile) model.V2RayPingResult {
	endpoint := strings.TrimSpace(profile.Server)
	if endpoint != "" && profile.ServerPort > 0 {
		endpoint = net.JoinHostPort(endpoint, strconv.Itoa(profile.ServerPort))
	}
	return model.V2RayPingResult{
		ProfileID: profile.ID,
		Endpoint:  endpoint,
		Message:   "Not tested",
	}
}

func duplicateV2RayProfileIndexes(items []model.V2RayProfile, selectedID string, activeID string) map[int]bool {
	keptByKey := map[string]int{}
	scoreByKey := map[string]int{}
	remove := map[int]bool{}
	for idx, item := range items {
		profile := profiles.NormalizeV2RayProfile(item)
		key := v2rayDuplicateKey(profile)
		if key == "" {
			continue
		}
		currentScore := v2rayDuplicateKeepScore(profile.ID, selectedID, activeID)
		keptIdx, ok := keptByKey[key]
		if !ok {
			keptByKey[key] = idx
			scoreByKey[key] = currentScore
			continue
		}
		if currentScore > scoreByKey[key] {
			remove[keptIdx] = true
			keptByKey[key] = idx
			scoreByKey[key] = currentScore
			continue
		}
		remove[idx] = true
	}
	return remove
}

func v2rayDuplicateKeepScore(id string, selectedID string, activeID string) int {
	id = strings.TrimSpace(id)
	switch {
	case id != "" && id == strings.TrimSpace(activeID):
		return 90
	case id != "" && id == strings.TrimSpace(selectedID):
		return 80
	default:
		return 0
	}
}

func v2rayDuplicateKey(profile model.V2RayProfile) string {
	if strings.TrimSpace(profile.Server) == "" {
		return ""
	}
	credential := v2rayDuplicateCredential(profile)
	if credential == "" {
		return ""
	}
	return strings.Join([]string{
		profile.Protocol,
		strings.ToLower(profile.Server),
		strconv.Itoa(profile.ServerPort),
		credential,
		strconv.Itoa(profile.AlterID),
		strings.ToLower(profile.Security),
		profile.Flow,
		profile.PacketEncoding,
		profile.Network,
		strconv.FormatBool(profile.TLS),
		strings.ToLower(profile.SNI),
		strings.ToLower(profile.ALPN),
		strconv.FormatBool(profile.AllowInsecure),
		strings.ToLower(profile.UTLSFingerprint),
		profile.ECHConfigList,
		strconv.FormatBool(profile.Reality),
		profile.RealityPublicKey,
		profile.RealityShortID,
		profile.TransportPath,
		strings.ToLower(profile.TransportHost),
		profile.ServiceName,
		profile.XHTTPMode,
		profile.XHTTPExtra,
		strconv.Itoa(profile.WebSocketEarlyData),
		strings.ToLower(profile.WebSocketEarlyDataHeader),
		profile.Username,
		profile.ShadowsocksMethod,
		strconv.FormatBool(profile.UoT),
		strconv.Itoa(profile.UoTVersion),
		profile.HysteriaAuth,
		strconv.Itoa(profile.HysteriaUDPIdleTimeout),
		profile.HysteriaMasquerade,
		profile.HTTPHeaders,
		profile.WireGuardLocalAddresses,
		profile.WireGuardPeerPublicKey,
		profile.WireGuardPreSharedKey,
		profile.WireGuardAllowedIPs,
		strconv.Itoa(profile.WireGuardKeepAlive),
		strconv.Itoa(profile.WireGuardMTU),
		profile.WireGuardReserved,
		strconv.FormatBool(profile.WireGuardNoKernelTun),
		profile.WireGuardDomainStrategy,
	}, "\x1f")
}

func v2rayDuplicateCredential(profile model.V2RayProfile) string {
	switch profile.Protocol {
	case model.V2RayProtocolTrojan, model.V2RayProtocolShadowsocks:
		return strings.TrimSpace(profile.Password)
	case model.V2RayProtocolHysteria2:
		return strings.TrimSpace(profile.HysteriaAuth)
	case model.V2RayProtocolWireGuard:
		return strings.TrimSpace(profile.WireGuardSecretKey)
	case model.V2RayProtocolSOCKS, model.V2RayProtocolHTTP:
		return strings.TrimSpace(profile.Username + ":" + profile.Password)
	default:
		return strings.TrimSpace(profile.UUID)
	}
}

func (a *App) logV2RayStartDiagnostics(profile model.V2RayProfile, settings model.V2RaySettingsProfile, configBytes int) {
	profile = profiles.NormalizeV2RayProfile(profile)
	settings = profiles.NormalizeV2RaySettingsProfile(settings)
	lines := []string{
		fmt.Sprintf("V2Ray profile: protocol=%s network=%s tls=%t reality=%t flow=%q packet_encoding=%q", profile.Protocol, profile.Network, profile.TLS, profile.Reality, profile.Flow, profile.PacketEncoding),
		fmt.Sprintf("V2Ray transport: endpoint fields redacted xhttp_mode=%q xhttp_extra=%t allow_insecure=%t utls=%q ech=%t ws_early_data=%d", profile.XHTTPMode, strings.TrimSpace(profile.XHTTPExtra) != "", profile.AllowInsecure, profile.UTLSFingerprint, strings.TrimSpace(profile.ECHConfigList) != "", profile.WebSocketEarlyData),
		fmt.Sprintf("V2Ray local proxy: inbound=%s system_proxy=%t allow_lan=%t tun=%t tun_interface=%q tun_mtu=%d tun_ipv6=%t config_bytes=%d", settings.InboundType, settings.SetSystemProxy && !settings.TunEnabled, settings.AllowLAN, settings.TunEnabled, settings.TunInterfaceName, settings.TunMTU, settings.TunIPv6, configBytes),
	}
	if settings.TunEnabled {
		lines = append(lines, "V2Ray TUN note: DNS stays managed by the operating system; local router DNS may remain local unless the resolver path is routed through TUN")
	}
	if profile.Network == "ws" {
		lines = append(lines, "V2Ray WS route: endpoint fields redacted")
		if profile.TLS && profile.UTLSFingerprint == "" {
			lines = append(lines, "V2Ray WS note: no uTLS fingerprint is set; some CDN-fronted profiles reject non-browser TLS handshakes with HTTP 403")
		}
	}
	for _, line := range lines {
		a.handleLogForActiveRuntime(model.RuntimeTypeV2Ray, profile.ID, line)
	}
}

func (a *App) startV2RayUpstreamWebSocketProbe(profile model.V2RayProfile) {
	profile = profiles.NormalizeV2RayProfile(profile)
	if profile.Network != "ws" {
		return
	}
	profileID := profile.ID
	go func() {
		targetURL := v2rayWebSocketProbeURL(profile)
		hostHeader := v2rayWebSocketHostHeader(profile)
		tlsServerName := v2rayTLSServerName(profile)
		a.handleLogForActiveRuntime(model.RuntimeTypeV2Ray, profileID, "V2Ray upstream WS probe: checking route")

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			a.handleLogForActiveRuntime(model.RuntimeTypeV2Ray, profileID, "V2Ray upstream WS probe build failed: "+err.Error())
			return
		}
		if hostHeader != "" {
			req.Host = hostHeader
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", randomWebSocketKey())

		client := &http.Client{
			Transport: v2rayWebSocketProbeTransport(profile, tlsServerName),
			Timeout:   9 * time.Second,
		}
		defer closeHTTPClientIdleConnections(client)
		started := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(started).Milliseconds()
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			a.handleLogForActiveRuntime(model.RuntimeTypeV2Ray, profileID, fmt.Sprintf("V2Ray upstream WS probe failed after %d ms: %v", elapsed, err))
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 160))
		if resp.StatusCode == http.StatusSwitchingProtocols {
			a.handleLogForActiveRuntime(model.RuntimeTypeV2Ray, profileID, fmt.Sprintf("V2Ray upstream WS probe accepted upgrade in %d ms", elapsed))
			return
		}
		a.handleLogForActiveRuntime(model.RuntimeTypeV2Ray, profileID, fmt.Sprintf("V2Ray upstream WS probe returned HTTP %d after %d ms; upstream refused the WebSocket handshake before VLESS auth", resp.StatusCode, elapsed))
	}()
}

func v2rayWebSocketProbeTransport(profile model.V2RayProfile, tlsServerName string) *http.Transport {
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	if profile.TLS {
		transport.TLSClientConfig = &tls.Config{
			ServerName:         tlsServerName,
			InsecureSkipVerify: profile.AllowInsecure,
		}
	}
	return transport
}

func v2rayWebSocketProbeURL(profile model.V2RayProfile) string {
	scheme := "http"
	if profile.TLS {
		scheme = "https"
	}
	path, rawQuery := v2rayWebSocketPathParts(profile.TransportPath)
	return (&url.URL{
		Scheme:   scheme,
		Host:     net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort)),
		Path:     path,
		RawQuery: rawQuery,
	}).String()
}

func v2rayWebSocketRequestPath(path string) string {
	requestPath, rawQuery := v2rayWebSocketPathParts(path)
	if rawQuery != "" {
		return requestPath + "?" + rawQuery
	}
	return requestPath
}

func v2rayWebSocketPathParts(path string) (string, string) {
	requestPath := strings.TrimSpace(path)
	if requestPath == "" {
		requestPath = "/"
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	if idx := strings.IndexByte(requestPath, '?'); idx >= 0 {
		return requestPath[:idx], requestPath[idx+1:]
	}
	return requestPath, ""
}

func v2rayWebSocketHostHeader(profile model.V2RayProfile) string {
	return strings.TrimSpace(profile.TransportHost)
}

// v2rayTLSServerName is the name a TLS handshake should ask for: whichever of
// the fields that can hold one does, in the order a server reads them.
func v2rayTLSServerName(profile model.V2RayProfile) string {
	return whiteDNSVPNProfileHost(profiles.NormalizeV2RayProfile(profile))
}

func randomWebSocketKey() string {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return "dGhlIHNhbXBsZSBub25jZQ=="
	}
	return base64.StdEncoding.EncodeToString(key)
}

func proxyHealthHost(listenIP string) string {
	host := strings.TrimSpace(listenIP)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return "127.0.0.1"
	}
	return host
}

func selectedV2RayProfile(state model.AppState) (model.V2RayProfile, bool) {
	for _, profile := range state.V2RayProfiles {
		if profile.ID == state.SelectedV2RayProfileID {
			return profile, true
		}
	}
	return model.V2RayProfile{}, false
}

func selectedV2RaySettingsProfile(state model.AppState) (model.V2RaySettingsProfile, bool) {
	for _, profile := range state.V2RaySettingsProfiles {
		if profile.ID == state.SelectedV2RaySettingsID {
			return profile, true
		}
	}
	return model.V2RaySettingsProfile{}, false
}

func fetchV2RaySubscriptionDocument(ctx context.Context, rawURL string) (string, error) {
	return fetchV2RaySubscriptionDocumentWith(ctx, rawURL, http.DefaultClient)
}

// fetchV2RaySubscriptionDocumentWith fetches through a caller's client, which is
// how a subscription can be fetched through the running tunnel.
func fetchV2RaySubscriptionDocumentWith(ctx context.Context, rawURL string, base *http.Client) (string, error) {
	parsedURL, err := validateV2RaySubscriptionURL(rawURL)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, v2raySubscriptionTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "WhiteDNS-Desktop")

	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.CheckRedirect = checkSubscriptionRedirect
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, v2raySubscriptionMaxBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > v2raySubscriptionMaxBytes {
		return "", fmt.Errorf("subscription response is too large")
	}
	return string(raw), nil
}

func checkSubscriptionRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	for _, previous := range via {
		if previous.URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("subscription redirect from HTTPS to %s is not allowed", req.URL.Scheme)
		}
	}
	return nil
}

func validateV2RaySubscriptionURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsedURL == nil {
		return nil, fmt.Errorf("valid subscription URL is required")
	}
	// http and https, and nothing else — not file://, not ftp://.
	//
	// The phone refuses plain HTTP and the reason is good: a subscription
	// fetched in the clear is a server list anyone on the path can read and,
	// worse, replace, which in a censored network is the same adversary the VPN
	// exists to get past. But providers do serve them over HTTP, and refusing
	// outright means someone's own subscription cannot be used here while every
	// other client takes it. So it is allowed and marked: the interface says
	// which subscriptions arrive in the clear, every time it lists them, rather
	// than asking once and forgetting.
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("subscription URL must start with https:// or http://")
	}
	if strings.TrimSpace(parsedURL.Host) == "" {
		return nil, fmt.Errorf("subscription URL host is required")
	}
	return parsedURL, nil
}

func defaultV2RaySubscriptionName(parsedURL *url.URL) string {
	host := strings.TrimSpace(parsedURL.Hostname())
	if host == "" {
		host = "Subscription"
	}
	return host
}

func uniqueV2RaySubscriptionID(items []model.V2RaySubscription) string {
	existing := make(map[string]struct{}, len(items))
	for _, item := range items {
		existing[item.ID] = struct{}{}
	}
	baseID := time.Now().UnixNano()
	for attempt := 0; ; attempt++ {
		id := fmt.Sprintf("v2ray-subscription-%d-%d", baseID, attempt)
		if _, ok := existing[id]; !ok {
			return id
		}
	}
}

func findV2RaySubscription(state model.AppState, id string) (model.V2RaySubscription, bool) {
	idx := findV2RaySubscriptionIndex(state.V2RaySubscriptions, id)
	if idx == -1 {
		return model.V2RaySubscription{}, false
	}
	return state.V2RaySubscriptions[idx], true
}

func findV2RaySubscriptionOrZero(state model.AppState, id string) model.V2RaySubscription {
	subscription, _ := findV2RaySubscription(state, id)
	return subscription
}

func findV2RaySubscriptionIndex(items []model.V2RaySubscription, id string) int {
	for idx, item := range items {
		if item.ID == id {
			return idx
		}
	}
	return -1
}

func activeV2RaySubscriptionLocked(state model.AppState, subscriptionID string) bool {
	if state.Runtime.Status == model.RuntimeDisconnected || state.Runtime.ActiveConnectionID == "" {
		return false
	}
	for _, profile := range state.V2RayProfiles {
		if profile.ID == state.Runtime.ActiveConnectionID && profile.SubscriptionID == subscriptionID {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniqueImportedV2RayID(existingIDs map[string]struct{}, baseID int64, index int) string {
	for attempt := 0; ; attempt++ {
		id := fmt.Sprintf("v2ray-import-%d-%d-%d", baseID, index, attempt)
		if _, ok := existingIDs[id]; !ok {
			existingIDs[id] = struct{}{}
			return id
		}
	}
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

package profiles

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/resolver"
)

const (
	MaxInlineResolverEntries = 5000
	MaxInlineResolverBytes   = 1 << 20
	ResolverPreviewLimit     = 16
	MaxResolverPreviewLimit  = 10000
)

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() (model.AppState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return model.DefaultAppState(), nil
	}
	if err != nil {
		return model.AppState{}, err
	}

	var state model.AppState
	if err := json.Unmarshal(raw, &state); err != nil {
		return model.DefaultAppState(), nil
	}
	state, migrated, err := s.prepareStateLocked(state, false)
	if err != nil {
		return model.DefaultAppState(), nil
	}
	if migrated {
		_ = s.writeStateLocked(state)
	}
	return state, nil
}

func (s *Store) Save(state model.AppState) error {
	_, err := s.SaveState(state)
	return err
}

func (s *Store) SaveState(state model.AppState) (model.AppState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, _, err := s.prepareStateLocked(state, true)
	if err != nil {
		return state, err
	}
	persisted := state
	persisted.Runtime = model.DefaultAppState().Runtime
	if err := s.writeStateLocked(persisted); err != nil {
		return state, err
	}
	return state, nil
}

func (s *Store) ImportResolverFile(sourcePath string) (model.ResolverProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return model.ResolverProfile{}, fmt.Errorf("resolver file path is required")
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return model.ResolverProfile{}, err
	}
	if info.IsDir() {
		return model.ResolverProfile{}, fmt.Errorf("resolver import path must be a file")
	}

	id := fmt.Sprintf("resolver-import-%d", time.Now().UnixNano())
	dest := s.uniqueManagedResolverPathLocked(id)
	summary, err := normalizeResolverFileToManagedPath(sourcePath, dest)
	if err != nil {
		return model.ResolverProfile{}, err
	}
	if summary.Count == 0 {
		_ = os.Remove(dest)
		return model.ResolverProfile{}, fmt.Errorf("resolver file must contain at least one valid resolver")
	}

	name := strings.TrimSuffix(filepath.Base(sourcePath), filepath.Ext(sourcePath))
	if strings.TrimSpace(name) == "" {
		name = "Imported resolvers"
	}
	return model.ResolverProfile{
		ID:                   id,
		Name:                 name,
		ResolverSource:       "file",
		ResolverFile:         dest,
		ResolverCount:        summary.Count,
		ResolverPreview:      summary.Preview,
		ResolverInvalidCount: summary.InvalidCount,
	}, nil
}

func (s *Store) CreateManagedResolverProfile(name string, idPrefix string, reader io.Reader) (model.ResolverProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idPrefix = strings.TrimSpace(idPrefix)
	if idPrefix == "" {
		idPrefix = "resolver"
	}
	id := fmt.Sprintf("%s-%d", idPrefix, time.Now().UnixNano())
	dest := s.uniqueManagedResolverPathLocked(id)
	summary, err := normalizeResolverReaderToManagedPath(reader, dest)
	if err != nil {
		return model.ResolverProfile{}, err
	}
	if summary.Count == 0 {
		_ = os.Remove(dest)
		return model.ResolverProfile{}, fmt.Errorf("resolver profile must contain at least one valid resolver")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		name = "Scanned Resolvers"
	}
	return model.ResolverProfile{
		ID:                   id,
		Name:                 name,
		ResolverSource:       "file",
		ResolverFile:         dest,
		ResolverCount:        summary.Count,
		ResolverPreview:      summary.Preview,
		ResolverInvalidCount: summary.InvalidCount,
	}, nil
}

func ReadResolverPreviewPage(profile model.ResolverProfile, offset, limit int) (model.ResolverPreviewPage, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > MaxResolverPreviewLimit {
		limit = MaxResolverPreviewLimit
	}
	page := model.ResolverPreviewPage{
		Offset: offset,
		Limit:  limit,
		Total:  resolverProfileCount(profile),
	}

	if resolverProfileIsFileBacked(profile) {
		file, err := os.Open(profile.ResolverFile)
		if err != nil {
			return page, err
		}
		defer file.Close()
		resolvers, total, err := readNormalizedResolverPage(file, offset, limit)
		if err != nil {
			return page, err
		}
		page.Resolvers = resolvers
		if total > page.Total {
			page.Total = total
		}
		page.HasMore = page.Offset+len(page.Resolvers) < page.Total
		return page, nil
	}

	validation := resolver.ValidateText(profile.ResolverText)
	page.Total = len(validation.NormalizedResolvers)
	if offset >= page.Total {
		return page, nil
	}
	end := offset + limit
	if end > page.Total {
		end = page.Total
	}
	page.Resolvers = append([]string(nil), validation.NormalizedResolvers[offset:end]...)
	page.HasMore = end < page.Total
	return page, nil
}

func (s *Store) prepareStateLocked(state model.AppState, preserveRuntime bool) (model.AppState, bool, error) {
	if preserveRuntime {
		state = NormalizeStatePreservingRuntime(state)
	} else {
		state = NormalizeState(state)
	}
	migrated, err := s.migrateLargeInlineResolversLocked(&state)
	if err != nil {
		return state, migrated, err
	}
	if preserveRuntime {
		state = NormalizeStatePreservingRuntime(state)
	} else {
		state = NormalizeState(state)
	}
	return state, migrated, nil
}

func (s *Store) writeStateLocked(state model.AppState) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.%d.tmp", s.path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func NormalizeState(state model.AppState) model.AppState {
	defaults := model.DefaultAppState()
	if state.Theme == "" {
		state.Theme = defaults.Theme
	}

	state.ConnectionProfiles = normalizeConnections(state.ConnectionProfiles)
	state.ResolverProfiles = normalizeResolvers(state.ResolverProfiles)
	state.SettingsProfiles = normalizeSettingsProfiles(state.SettingsProfiles)
	state.V2RayProfiles = normalizeV2RayProfiles(state.V2RayProfiles)
	state.V2RaySubscriptions = normalizeV2RaySubscriptions(state.V2RaySubscriptions)
	state.V2RaySettingsProfiles = normalizeV2RaySettingsProfiles(state.V2RaySettingsProfiles)
	state.WhiteVPN = model.NormalizeWhiteVPNSettings(state.WhiteVPN)
	state.WhiteDNSVPNFrontingIPs = NormalizeWhiteDNSVPNFrontingIPs(state.WhiteDNSVPNFrontingIPs)

	if !hasConnection(state.ConnectionProfiles, state.SelectedConnectionProfileID) {
		state.SelectedConnectionProfileID = state.ConnectionProfiles[0].ID
	}
	if !hasResolver(state.ResolverProfiles, state.SelectedResolverProfileID) {
		state.SelectedResolverProfileID = state.ResolverProfiles[0].ID
	}
	if !hasSettings(state.SettingsProfiles, state.SelectedSettingsProfileID) {
		state.SelectedSettingsProfileID = state.SettingsProfiles[0].ID
	}
	if len(state.V2RayProfiles) == 0 {
		state.SelectedV2RayProfileID = ""
	} else if !hasV2Ray(state.V2RayProfiles, state.SelectedV2RayProfileID) {
		state.SelectedV2RayProfileID = state.V2RayProfiles[0].ID
	}
	if !hasV2RaySettings(state.V2RaySettingsProfiles, state.SelectedV2RaySettingsID) {
		state.SelectedV2RaySettingsID = state.V2RaySettingsProfiles[0].ID
	}

	resolverIDs := map[string]struct{}{}
	for _, profile := range state.ResolverProfiles {
		resolverIDs[profile.ID] = struct{}{}
	}
	for idx := range state.ConnectionProfiles {
		if _, ok := resolverIDs[state.ConnectionProfiles[idx].ResolverProfileID]; !ok {
			state.ConnectionProfiles[idx].ResolverProfileID = ""
		}
	}

	state.Runtime = defaults.Runtime
	return state
}

const MaxWhiteDNSVPNFrontingIPs = 10

func NormalizeWhiteDNSVPNFrontingIPs(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.To4() == nil {
			continue
		}
		normalized := ip.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
		if len(out) >= MaxWhiteDNSVPNFrontingIPs {
			break
		}
	}
	if len(out) == 0 {
		return []string{}
	}
	return out
}

func NormalizeStatePreservingRuntime(state model.AppState) model.AppState {
	runtimeState := state.Runtime
	state = NormalizeState(state)
	if runtimeState.Status != "" {
		state.Runtime = runtimeState
	}
	return state
}

func normalizeConnections(profiles []model.ConnectionProfile) []model.ConnectionProfile {
	if len(profiles) == 0 {
		return []model.ConnectionProfile{model.DefaultConnectionProfile()}
	}
	out := make([]model.ConnectionProfile, 0, len(profiles))
	seen := map[string]struct{}{}
	for idx, profile := range profiles {
		profile.ID = strings.TrimSpace(profile.ID)
		if profile.ID == "" {
			profile.ID = fmt.Sprintf("profile-%d", time.Now().UnixMilli()+int64(idx))
		}
		if _, ok := seen[profile.ID]; ok {
			continue
		}
		seen[profile.ID] = struct{}{}
		profile.Name = strings.TrimSpace(profile.Name)
		if profile.Name == "" {
			profile.Name = fmt.Sprintf("Connection %d", len(out)+1)
		}
		profile.ImportType = model.NormalizeImportType(profile.ImportType)
		profile.Domain = strings.TrimSpace(strings.TrimSuffix(profile.Domain, "."))
		profile.EncryptionKey = strings.TrimSpace(profile.EncryptionKey)
		if profile.EncryptionMethod < 0 || profile.EncryptionMethod > 5 {
			profile.EncryptionMethod = 1
		}
		profile.ResolverProfileID = strings.TrimSpace(profile.ResolverProfileID)
		out = append(out, profile)
	}
	if len(out) == 0 {
		return []model.ConnectionProfile{model.DefaultConnectionProfile()}
	}
	return out
}

func normalizeResolvers(profiles []model.ResolverProfile) []model.ResolverProfile {
	out := make([]model.ResolverProfile, 0, len(profiles)+1)
	seen := map[string]struct{}{}
	defaultSeen := false
	customCount := 0

	for _, profile := range profiles {
		profile.ID = strings.TrimSpace(profile.ID)
		if profile.ID == "" {
			continue
		}
		if _, ok := seen[profile.ID]; ok {
			continue
		}
		seen[profile.ID] = struct{}{}
		profile.Name = strings.TrimSpace(profile.Name)
		if profile.ID == model.DefaultResolverProfileID {
			defaults := model.DefaultResolverProfile()
			if profile.Name == "" {
				profile.Name = defaults.Name
			}
			if !resolverProfileIsFileBacked(profile) && strings.TrimSpace(profile.ResolverText) == "" {
				profile.ResolverText = defaults.ResolverText
			}
			profile = normalizeResolverProfileMetadata(profile)
			defaultSeen = true
			out = append(out, profile)
			continue
		}
		if profile.Name == "" {
			profile.Name = fmt.Sprintf("Resolvers %d", customCount+1)
		}
		profile = normalizeResolverProfileMetadata(profile)
		out = append(out, profile)
		customCount++
	}

	if !defaultSeen {
		return append([]model.ResolverProfile{model.DefaultResolverProfile()}, out...)
	}
	if len(out) == 0 {
		return []model.ResolverProfile{model.DefaultResolverProfile()}
	}
	return out
}

func normalizeSettingsProfiles(profiles []model.SettingsProfile) []model.SettingsProfile {
	out := make([]model.SettingsProfile, 0, len(profiles)+1)
	seen := map[string]struct{}{}
	defaultSeen := false

	for _, profile := range profiles {
		profile = normalizeSettingsProfile(profile)
		if profile.ID == "" {
			continue
		}
		if _, ok := seen[profile.ID]; ok {
			continue
		}
		seen[profile.ID] = struct{}{}
		if profile.ID == model.DefaultSettingsProfileID {
			defaultSeen = true
			out = append(out, model.DefaultSettingsProfile())
			continue
		}
		out = append(out, profile)
	}
	if !defaultSeen {
		return append([]model.SettingsProfile{model.DefaultSettingsProfile()}, out...)
	}
	if len(out) == 0 {
		return []model.SettingsProfile{model.DefaultSettingsProfile()}
	}
	return out
}

func normalizeV2RayProfiles(profiles []model.V2RayProfile) []model.V2RayProfile {
	if len(profiles) == 0 {
		return []model.V2RayProfile{}
	}
	out := make([]model.V2RayProfile, 0, len(profiles))
	seen := map[string]struct{}{}
	for idx, profile := range profiles {
		profile = NormalizeV2RayProfile(profile)
		if isEmptyDefaultV2RayProfile(profile) {
			continue
		}
		if profile.ID == "" {
			profile.ID = fmt.Sprintf("v2ray-%d", time.Now().UnixMilli()+int64(idx))
		}
		if _, ok := seen[profile.ID]; ok {
			continue
		}
		seen[profile.ID] = struct{}{}
		out = append(out, profile)
	}
	if len(out) == 0 {
		return []model.V2RayProfile{}
	}
	return out
}

func normalizeV2RaySubscriptions(subscriptions []model.V2RaySubscription) []model.V2RaySubscription {
	if len(subscriptions) == 0 {
		return []model.V2RaySubscription{}
	}
	out := make([]model.V2RaySubscription, 0, len(subscriptions))
	seen := map[string]struct{}{}
	for idx, subscription := range subscriptions {
		subscription = NormalizeV2RaySubscription(subscription)
		if subscription.ID == "" {
			subscription.ID = fmt.Sprintf("v2ray-subscription-%d", time.Now().UnixMilli()+int64(idx))
		}
		if subscription.URL == "" {
			continue
		}
		if _, ok := seen[subscription.ID]; ok {
			continue
		}
		seen[subscription.ID] = struct{}{}
		out = append(out, subscription)
	}
	return out
}

func isEmptyDefaultV2RayProfile(profile model.V2RayProfile) bool {
	return profile.ID == model.DefaultV2RayProfileID &&
		strings.TrimSpace(profile.Server) == "" &&
		strings.TrimSpace(profile.UUID) == "" &&
		strings.TrimSpace(profile.Password) == ""
}

func normalizeV2RaySettingsProfiles(profiles []model.V2RaySettingsProfile) []model.V2RaySettingsProfile {
	if len(profiles) == 0 {
		return []model.V2RaySettingsProfile{model.DefaultV2RaySettingsProfile()}
	}
	out := make([]model.V2RaySettingsProfile, 0, len(profiles))
	seen := map[string]struct{}{}
	for idx, profile := range profiles {
		profile = NormalizeV2RaySettingsProfile(profile)
		if profile.ID == "" {
			profile.ID = fmt.Sprintf("v2ray-settings-%d", time.Now().UnixMilli()+int64(idx))
		}
		if _, ok := seen[profile.ID]; ok {
			continue
		}
		seen[profile.ID] = struct{}{}
		if profile.ID == model.DefaultV2RaySettingsID {
			out = append(out, model.DefaultV2RaySettingsProfile())
			continue
		}
		out = append(out, profile)
	}
	if len(out) == 0 {
		return []model.V2RaySettingsProfile{model.DefaultV2RaySettingsProfile()}
	}
	return out
}

func normalizeResolverProfileMetadata(profile model.ResolverProfile) model.ResolverProfile {
	profile.ResolverSource = strings.ToLower(strings.TrimSpace(profile.ResolverSource))
	profile.ResolverFile = strings.TrimSpace(profile.ResolverFile)
	if resolverProfileIsFileBacked(profile) {
		profile.ResolverSource = "file"
		profile.ResolverText = ""
		if profile.ResolverCount < 0 {
			profile.ResolverCount = 0
		}
		if profile.ResolverInvalidCount < 0 {
			profile.ResolverInvalidCount = 0
		}
		if len(profile.ResolverPreview) > ResolverPreviewLimit {
			profile.ResolverPreview = append([]string(nil), profile.ResolverPreview[:ResolverPreviewLimit]...)
		} else if profile.ResolverPreview != nil {
			profile.ResolverPreview = append([]string(nil), profile.ResolverPreview...)
		}
		return profile
	}

	profile.ResolverSource = "inline"
	profile.ResolverFile = ""
	profile.ResolverCount = 0
	profile.ResolverPreview = nil
	profile.ResolverInvalidCount = 0
	if !ResolverTextShouldBeFileBacked(profile.ResolverText) {
		profile.ResolverText = resolver.NormalizeText(profile.ResolverText)
	}
	return profile
}

func NormalizeV2RayProfile(profile model.V2RayProfile) model.V2RayProfile {
	defaults := model.DefaultV2RayProfile()
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	profile.SubscriptionID = strings.TrimSpace(profile.SubscriptionID)
	if profile.Name == "" {
		profile.Name = "V2Ray Connection"
	}
	switch strings.ToLower(strings.TrimSpace(profile.Protocol)) {
	case model.V2RayProtocolVMess:
		profile.Protocol = model.V2RayProtocolVMess
	case model.V2RayProtocolTrojan:
		profile.Protocol = model.V2RayProtocolTrojan
	case model.V2RayProtocolShadowsocks, "ss":
		profile.Protocol = model.V2RayProtocolShadowsocks
	case model.V2RayProtocolHysteria2, "hy2", "hysteria":
		profile.Protocol = model.V2RayProtocolHysteria2
	case model.V2RayProtocolWireGuard:
		profile.Protocol = model.V2RayProtocolWireGuard
	case model.V2RayProtocolSOCKS, "socks5":
		profile.Protocol = model.V2RayProtocolSOCKS
	case model.V2RayProtocolHTTP, "http-proxy", "https-proxy":
		profile.Protocol = model.V2RayProtocolHTTP
	default:
		profile.Protocol = model.V2RayProtocolVLESS
	}
	profile.Server = strings.TrimSpace(strings.TrimSuffix(profile.Server, "."))
	if profile.ServerPort <= 0 || profile.ServerPort > 65535 {
		profile.ServerPort = defaults.ServerPort
	}
	profile.UUID = strings.TrimSpace(profile.UUID)
	profile.Password = strings.TrimSpace(profile.Password)
	if profile.AlterID < 0 {
		profile.AlterID = 0
	}
	profile.Security = strings.ToLower(strings.TrimSpace(profile.Security))
	if profile.Security == "" {
		profile.Security = "auto"
	}
	profile.Flow = strings.TrimSpace(profile.Flow)
	profile.PacketEncoding = strings.TrimSpace(profile.PacketEncoding)
	network := strings.ToLower(strings.TrimSpace(profile.Network))
	network = strings.ReplaceAll(strings.ReplaceAll(network, "-", ""), "_", "")
	switch network {
	case "raw", "tcp":
		profile.Network = "tcp"
	case "kcp", "mkcp":
		profile.Network = "kcp"
	case "ws", "websocket":
		profile.Network = "ws"
	case "grpc":
		profile.Network = "grpc"
	case "http", "h2":
		profile.Network = "http"
	case "quic":
		profile.Network = "quic"
	case "httpupgrade":
		profile.Network = "httpupgrade"
	case "xhttp", "splithttp":
		profile.Network = "xhttp"
	default:
		profile.Network = "tcp"
	}
	profile.SNI = strings.TrimSpace(profile.SNI)
	profile.ALPN = strings.TrimSpace(profile.ALPN)
	profile.UTLSFingerprint = strings.TrimSpace(profile.UTLSFingerprint)
	profile.ECHConfigList = strings.TrimSpace(profile.ECHConfigList)
	profile.RealityPublicKey = strings.TrimSpace(profile.RealityPublicKey)
	profile.RealityShortID = strings.TrimSpace(profile.RealityShortID)
	profile.TransportPath = strings.TrimSpace(profile.TransportPath)
	profile.TransportHost = strings.TrimSpace(profile.TransportHost)
	profile.ServiceName = strings.TrimSpace(profile.ServiceName)
	profile.XHTTPMode = strings.TrimSpace(profile.XHTTPMode)
	profile.XHTTPExtra = strings.TrimSpace(profile.XHTTPExtra)
	if profile.WebSocketEarlyData < 0 {
		profile.WebSocketEarlyData = 0
	}
	profile.WebSocketEarlyDataHeader = strings.TrimSpace(profile.WebSocketEarlyDataHeader)
	if profile.WebSocketEarlyData > 0 && profile.WebSocketEarlyDataHeader == "" {
		profile.WebSocketEarlyDataHeader = "Sec-WebSocket-Protocol"
	}
	if profile.Reality {
		profile.TLS = true
	}
	if profile.Protocol == model.V2RayProtocolHysteria2 {
		profile.TLS = true
	}
	profile.Username = strings.TrimSpace(profile.Username)
	profile.ShadowsocksMethod = strings.TrimSpace(profile.ShadowsocksMethod)
	if profile.ShadowsocksMethod == "" {
		profile.ShadowsocksMethod = defaults.ShadowsocksMethod
	}
	if profile.UoTVersion <= 0 {
		profile.UoTVersion = defaults.UoTVersion
	}
	profile.HysteriaAuth = strings.TrimSpace(profile.HysteriaAuth)
	if profile.HysteriaUDPIdleTimeout < 0 {
		profile.HysteriaUDPIdleTimeout = 0
	}
	profile.HysteriaMasquerade = strings.TrimSpace(profile.HysteriaMasquerade)
	profile.HTTPHeaders = strings.TrimSpace(profile.HTTPHeaders)
	profile.WireGuardSecretKey = strings.TrimSpace(profile.WireGuardSecretKey)
	profile.WireGuardLocalAddresses = normalizeDelimitedText(profile.WireGuardLocalAddresses)
	if profile.WireGuardLocalAddresses == "" {
		profile.WireGuardLocalAddresses = defaults.WireGuardLocalAddresses
	}
	profile.WireGuardPeerPublicKey = strings.TrimSpace(profile.WireGuardPeerPublicKey)
	profile.WireGuardPreSharedKey = strings.TrimSpace(profile.WireGuardPreSharedKey)
	profile.WireGuardAllowedIPs = normalizeDelimitedText(profile.WireGuardAllowedIPs)
	if profile.WireGuardAllowedIPs == "" {
		profile.WireGuardAllowedIPs = defaults.WireGuardAllowedIPs
	}
	if profile.WireGuardKeepAlive < 0 {
		profile.WireGuardKeepAlive = 0
	}
	if profile.WireGuardMTU <= 0 {
		profile.WireGuardMTU = defaults.WireGuardMTU
	}
	profile.WireGuardReserved = normalizeDelimitedText(profile.WireGuardReserved)
	switch strings.TrimSpace(profile.WireGuardDomainStrategy) {
	case "ForceIPv6v4", "ForceIPv6", "ForceIPv4v6", "ForceIPv4", "ForceIP":
	default:
		profile.WireGuardDomainStrategy = defaults.WireGuardDomainStrategy
	}
	profile.OutboundSettings = strings.TrimSpace(profile.OutboundSettings)
	profile.StreamSettings = strings.TrimSpace(profile.StreamSettings)
	return profile
}

func NormalizeV2RaySubscription(subscription model.V2RaySubscription) model.V2RaySubscription {
	subscription.ID = strings.TrimSpace(subscription.ID)
	subscription.Name = strings.TrimSpace(subscription.Name)
	subscription.URL = strings.TrimSpace(subscription.URL)
	subscription.LastUpdatedAt = strings.TrimSpace(subscription.LastUpdatedAt)
	subscription.LastError = strings.TrimSpace(subscription.LastError)
	if subscription.Name == "" {
		subscription.Name = "V2Ray Subscription"
	}
	if subscription.ImportedCount < 0 {
		subscription.ImportedCount = 0
	}
	return subscription
}

func NormalizeV2RaySettingsProfile(profile model.V2RaySettingsProfile) model.V2RaySettingsProfile {
	defaults := model.DefaultV2RaySettingsProfile()
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = "V2Ray Settings"
	}
	profile.ListenIP = strings.TrimSpace(profile.ListenIP)
	if v2RayListenAllowsLAN(profile.ListenIP) {
		profile.AllowLAN = true
	}
	if profile.AllowLAN {
		profile.ListenIP = "0.0.0.0"
	}
	if strings.TrimSpace(profile.ListenIP) == "" {
		profile.ListenIP = defaults.ListenIP
	}
	if profile.ListenPort <= 0 || profile.ListenPort > 65535 {
		profile.ListenPort = defaults.ListenPort
	}
	switch strings.ToLower(strings.TrimSpace(profile.InboundType)) {
	case "mixed", "socks", "http":
		profile.InboundType = strings.ToLower(strings.TrimSpace(profile.InboundType))
	default:
		profile.InboundType = defaults.InboundType
	}
	missingTunSettings := !profile.TunEnabled &&
		profile.TunMTU == 0 &&
		!profile.TunIPv6 &&
		strings.TrimSpace(profile.TunInterfaceName) == ""
	if profile.TunMTU < 576 || profile.TunMTU > 9000 {
		profile.TunMTU = defaults.TunMTU
	}
	if strings.TrimSpace(profile.TunInterfaceName) == "" {
		profile.TunInterfaceName = defaults.TunInterfaceName
	} else {
		profile.TunInterfaceName = strings.TrimSpace(profile.TunInterfaceName)
	}
	if missingTunSettings {
		profile.TunIPv6 = defaults.TunIPv6
	}
	switch strings.ToUpper(strings.TrimSpace(profile.LogLevel)) {
	case "DEBUG", "INFO", "WARN", "ERROR":
		profile.LogLevel = strings.ToUpper(strings.TrimSpace(profile.LogLevel))
	default:
		profile.LogLevel = defaults.LogLevel
	}
	return profile
}

func v2RayListenAllowsLAN(value string) bool {
	switch strings.TrimSpace(value) {
	case "0.0.0.0", "::":
		return true
	default:
		return false
	}
}

func normalizeDelimitedText(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			out = append(out, item)
		}
	}
	return strings.Join(out, ", ")
}

func ResolverTextShouldBeFileBacked(raw string) bool {
	if len(raw) > MaxInlineResolverBytes {
		return true
	}
	if raw == "" {
		return false
	}
	entries := 0
	for _, line := range strings.Split(strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, ",;") {
			for _, part := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' }) {
				if strings.TrimSpace(part) != "" {
					entries++
				}
			}
		} else {
			entries++
		}
		if entries > MaxInlineResolverEntries {
			return true
		}
	}
	return false
}

func resolverProfileIsFileBacked(profile model.ResolverProfile) bool {
	return strings.EqualFold(strings.TrimSpace(profile.ResolverSource), "file") && strings.TrimSpace(profile.ResolverFile) != ""
}

func resolverProfileCount(profile model.ResolverProfile) int {
	if resolverProfileIsFileBacked(profile) {
		return profile.ResolverCount
	}
	if strings.TrimSpace(profile.ResolverText) == "" {
		return 0
	}
	return len(resolver.ValidateText(profile.ResolverText).NormalizedResolvers)
}

func NormalizeSettingsProfile(profile model.SettingsProfile) model.SettingsProfile {
	return normalizeSettingsProfile(profile)
}

func normalizeSettingsProfile(profile model.SettingsProfile) model.SettingsProfile {
	defaults := model.DefaultSettingsProfile()
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = "Settings"
	}
	profile.ImportType = model.NormalizeImportType(profile.ImportType)
	if strings.TrimSpace(profile.ListenIP) == "" {
		profile.ListenIP = defaults.ListenIP
	}
	if profile.ListenPort <= 0 || profile.ListenPort > 65535 {
		profile.ListenPort = defaults.ListenPort
	}
	if profile.SOCKSUsername == "" {
		profile.SOCKSUsername = defaults.SOCKSUsername
	}
	if profile.SOCKSPassword == "" {
		profile.SOCKSPassword = defaults.SOCKSPassword
	}
	profile.SingBoxEnabled = true
	switch strings.ToLower(strings.TrimSpace(profile.SingBoxInboundType)) {
	case "mixed", "socks", "http":
		profile.SingBoxInboundType = strings.ToLower(strings.TrimSpace(profile.SingBoxInboundType))
	default:
		profile.SingBoxInboundType = defaults.SingBoxInboundType
	}
	if strings.TrimSpace(profile.StormDNSListenIP) == "" {
		profile.StormDNSListenIP = defaults.StormDNSListenIP
	}
	if profile.StormDNSListenPort <= 0 || profile.StormDNSListenPort > 65535 {
		profile.StormDNSListenPort = defaults.StormDNSListenPort
	}
	if profile.LocalDNSPort <= 0 || profile.LocalDNSPort > 65535 {
		profile.LocalDNSPort = defaults.LocalDNSPort
	}
	profile.BalancingStrategy = clamp(profile.BalancingStrategy, 1, 8, defaults.BalancingStrategy)
	if profile.ImportType == model.ImportTypeMasterDNS {
		profile.UploadDuplication = clamp(profile.UploadDuplication, 0, 10, defaults.UploadDuplication)
		profile.DownloadDuplication = clamp(profile.DownloadDuplication, profile.UploadDuplication, 12, defaults.DownloadDuplication)
	} else {
		profile.UploadDuplication = clamp(profile.UploadDuplication, 1, 90, defaults.UploadDuplication)
		profile.DownloadDuplication = clamp(profile.DownloadDuplication, 1, 90, defaults.DownloadDuplication)
	}
	if profile.ImportType == model.ImportTypeMasterDNS && strings.TrimSpace(profile.MTUServersFileName) == "" {
		profile.MTUServersFileName = defaults.MTUServersFileName
	}
	if strings.TrimSpace(profile.MTUServersFileFormat) == "" {
		profile.MTUServersFileFormat = defaults.MTUServersFileFormat
	}
	if strings.TrimSpace(profile.MTUUsingSectionSeparatorText) == "" {
		profile.MTUUsingSectionSeparatorText = defaults.MTUUsingSectionSeparatorText
	}
	if strings.TrimSpace(profile.MTURemovedServerLogFormat) == "" {
		profile.MTURemovedServerLogFormat = defaults.MTURemovedServerLogFormat
	}
	if strings.TrimSpace(profile.MTUAddedServerLogFormat) == "" {
		profile.MTUAddedServerLogFormat = defaults.MTUAddedServerLogFormat
	}
	if strings.TrimSpace(profile.MTUReactiveAddedServerLogFormat) == "" {
		profile.MTUReactiveAddedServerLogFormat = defaults.MTUReactiveAddedServerLogFormat
	}
	profile.UploadCompression = clamp(profile.UploadCompression, 0, 3, defaults.UploadCompression)
	profile.DownloadCompression = clamp(profile.DownloadCompression, 0, 3, defaults.DownloadCompression)
	profile.MinUploadMTU = clamp(profile.MinUploadMTU, 1, 4096, defaults.MinUploadMTU)
	profile.MinDownloadMTU = clamp(profile.MinDownloadMTU, 1, 8192, defaults.MinDownloadMTU)
	profile.MaxUploadMTU = clamp(profile.MaxUploadMTU, profile.MinUploadMTU, 4096, defaults.MaxUploadMTU)
	profile.MaxDownloadMTU = clamp(profile.MaxDownloadMTU, profile.MinDownloadMTU, 8192, defaults.MaxDownloadMTU)
	profile.MTUTestRetriesResolvers = clamp(profile.MTUTestRetriesResolvers, 1, 30, defaults.MTUTestRetriesResolvers)
	profile.MTUTestParallelismResolvers = clamp(profile.MTUTestParallelismResolvers, 1, 1000, defaults.MTUTestParallelismResolvers)
	missingStartupLoss := !profile.MTUStartupLossVerifyEnabled &&
		profile.MTUStartupLossVerifySamples == 0 &&
		profile.MTUStartupLossVerifyMaxLossPct == 0 &&
		profile.MTUStartupLossVerifyCandidates == 0
	if missingStartupLoss {
		profile.MTUStartupLossVerifyEnabled = defaults.MTUStartupLossVerifyEnabled
		profile.MTUStartupLossVerifySamples = defaults.MTUStartupLossVerifySamples
		profile.MTUStartupLossVerifyMaxLossPct = defaults.MTUStartupLossVerifyMaxLossPct
		profile.MTUStartupLossVerifyCandidates = defaults.MTUStartupLossVerifyCandidates
	}
	profile.MTUStartupLossVerifySamples = clamp(profile.MTUStartupLossVerifySamples, 1, 30, defaults.MTUStartupLossVerifySamples)
	profile.MTUStartupLossVerifyMaxLossPct = clamp(profile.MTUStartupLossVerifyMaxLossPct, 0, 100, defaults.MTUStartupLossVerifyMaxLossPct)
	profile.MTUStartupLossVerifyCandidates = clamp(profile.MTUStartupLossVerifyCandidates, 1, 16, defaults.MTUStartupLossVerifyCandidates)
	missingRecheck := !profile.MTURecheckEnabled && profile.MTURecheckIntervalMinutes == 0
	if missingRecheck {
		profile.MTURecheckEnabled = defaults.MTURecheckEnabled
		profile.MTURecheckIntervalMinutes = defaults.MTURecheckIntervalMinutes
	}
	profile.MTURecheckIntervalMinutes = clamp(profile.MTURecheckIntervalMinutes, 0, 1440, defaults.MTURecheckIntervalMinutes)
	profile.MTUTestRetriesLogs = clamp(profile.MTUTestRetriesLogs, 1, 30, defaults.MTUTestRetriesLogs)
	profile.MTUTestParallelismLogs = clamp(profile.MTUTestParallelismLogs, 1, 1000, defaults.MTUTestParallelismLogs)
	switch strings.ToLower(strings.TrimSpace(profile.ConnectionStartupMode)) {
	case model.ConnectionStartupModeStandard, "fast", "":
		profile.ConnectionStartupMode = model.ConnectionStartupModeStandard
	case model.ConnectionStartupModeFullScan:
		profile.ConnectionStartupMode = model.ConnectionStartupModeFullScan
	default:
		profile.ConnectionStartupMode = defaults.ConnectionStartupMode
	}
	profile.RXTXWorkers = clamp(profile.RXTXWorkers, 1, 128, defaults.RXTXWorkers)
	profile.TunnelProcessWorkers = clamp(profile.TunnelProcessWorkers, 1, 128, defaults.TunnelProcessWorkers)
	profile.TXChannelSize = clamp(profile.TXChannelSize, 1, 1_000_000, defaults.TXChannelSize)
	profile.RXChannelSize = clamp(profile.RXChannelSize, 1, 1_000_000, defaults.RXChannelSize)
	profile.ResolverUDPConnectionPoolSize = clamp(profile.ResolverUDPConnectionPoolSize, 1, 4096, defaults.ResolverUDPConnectionPoolSize)
	profile.StreamQueueInitialCapacity = clamp(profile.StreamQueueInitialCapacity, 1, 1_000_000, defaults.StreamQueueInitialCapacity)
	profile.OrphanQueueInitialCapacity = clamp(profile.OrphanQueueInitialCapacity, 1, 1_000_000, defaults.OrphanQueueInitialCapacity)
	profile.DNSResponseFragmentStoreCapacity = clamp(profile.DNSResponseFragmentStoreCapacity, 1, 1_000_000, defaults.DNSResponseFragmentStoreCapacity)
	profile.MaxActiveStreams = clamp(profile.MaxActiveStreams, 1, 1_000_000, defaults.MaxActiveStreams)
	profile.SessionInitRetryLinearAfter = clamp(profile.SessionInitRetryLinearAfter, 0, 1000, defaults.SessionInitRetryLinearAfter)
	profile.SessionInitRacingCount = clamp(profile.SessionInitRacingCount, 1, 5, defaults.SessionInitRacingCount)
	profile.PingWatchdogSeconds = clamp(profile.PingWatchdogSeconds, 1, 86400, defaults.PingWatchdogSeconds)
	if profile.MTUTestTimeoutResolvers <= 0 {
		profile.MTUTestTimeoutResolvers = defaults.MTUTestTimeoutResolvers
	}
	if profile.MTUTestTimeoutLogs <= 0 {
		profile.MTUTestTimeoutLogs = defaults.MTUTestTimeoutLogs
	}
	if profile.TunnelPacketTimeoutSeconds <= 0 {
		profile.TunnelPacketTimeoutSeconds = defaults.TunnelPacketTimeoutSeconds
	}
	if profile.DispatcherIdlePollIntervalSec <= 0 {
		profile.DispatcherIdlePollIntervalSec = defaults.DispatcherIdlePollIntervalSec
	}
	if profile.LocalHandshakeTimeoutSeconds <= 0 {
		profile.LocalHandshakeTimeoutSeconds = defaults.LocalHandshakeTimeoutSeconds
	}
	if profile.SOCKSUDPAssociateReadTimeoutSec <= 0 {
		profile.SOCKSUDPAssociateReadTimeoutSec = defaults.SOCKSUDPAssociateReadTimeoutSec
	}
	if profile.ClientTerminalStreamRetentionSec <= 0 {
		profile.ClientTerminalStreamRetentionSec = defaults.ClientTerminalStreamRetentionSec
	}
	if profile.ClientCancelledSetupRetentionSec <= 0 {
		profile.ClientCancelledSetupRetentionSec = defaults.ClientCancelledSetupRetentionSec
	}
	if profile.SessionInitRetryBaseSeconds <= 0 {
		profile.SessionInitRetryBaseSeconds = defaults.SessionInitRetryBaseSeconds
	}
	if profile.SessionInitRetryStepSeconds <= 0 {
		profile.SessionInitRetryStepSeconds = defaults.SessionInitRetryStepSeconds
	}
	if profile.SessionInitRetryMaxSeconds <= 0 {
		profile.SessionInitRetryMaxSeconds = defaults.SessionInitRetryMaxSeconds
	}
	if profile.SessionInitBusyRetryIntervalSec <= 0 {
		profile.SessionInitBusyRetryIntervalSec = defaults.SessionInitBusyRetryIntervalSec
	}
	switch strings.ToLower(profile.StartupMode) {
	case "ask", "resolvers", "logs":
	default:
		profile.StartupMode = defaults.StartupMode
	}
	switch strings.ToUpper(profile.LogLevel) {
	case "DEBUG", "INFO", "WARN", "ERROR":
		profile.LogLevel = strings.ToUpper(profile.LogLevel)
	default:
		profile.LogLevel = defaults.LogLevel
	}
	return profile
}

func (s *Store) migrateLargeInlineResolversLocked(state *model.AppState) (bool, error) {
	migrated := false
	for idx := range state.ResolverProfiles {
		profile := state.ResolverProfiles[idx]
		if resolverProfileIsFileBacked(profile) || !ResolverTextShouldBeFileBacked(profile.ResolverText) {
			continue
		}

		dest := s.uniqueManagedResolverPathLocked(profile.ID)
		summary, err := normalizeResolverTextToManagedPath(profile.ResolverText, dest)
		if err != nil {
			return migrated, err
		}
		profile.ResolverSource = "file"
		profile.ResolverFile = dest
		profile.ResolverText = ""
		profile.ResolverCount = summary.Count
		profile.ResolverPreview = summary.Preview
		profile.ResolverInvalidCount = summary.InvalidCount
		state.ResolverProfiles[idx] = profile
		migrated = true
	}
	return migrated, nil
}

func (s *Store) uniqueManagedResolverPathLocked(profileID string) string {
	base := safeResolverFileBase(profileID)
	if base == "" {
		base = fmt.Sprintf("resolver-%d", time.Now().UnixNano())
	}
	dir := s.resolverDirLocked()
	path := filepath.Join(dir, base+".txt")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return path
	}
	for attempt := 1; ; attempt++ {
		path = filepath.Join(dir, fmt.Sprintf("%s-%d.txt", base, attempt))
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return path
		}
	}
}

func (s *Store) resolverDirLocked() string {
	return filepath.Join(filepath.Dir(s.path), "resolvers")
}

func safeResolverFileBase(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
		if b.Len() >= 80 {
			break
		}
	}
	return strings.Trim(b.String(), "-_")
}

func normalizeResolverFileToManagedPath(sourcePath, destPath string) (resolver.FileSummary, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return resolver.FileSummary{}, err
	}
	defer source.Close()
	return normalizeResolverReaderToManagedPath(source, destPath)
}

func normalizeResolverTextToManagedPath(rawText, destPath string) (resolver.FileSummary, error) {
	return normalizeResolverReaderToManagedPath(strings.NewReader(rawText), destPath)
}

func normalizeResolverReaderToManagedPath(reader io.Reader, destPath string) (resolver.FileSummary, error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return resolver.FileSummary{}, err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", destPath, time.Now().UnixNano())
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return resolver.FileSummary{}, err
	}
	summary, normalizeErr := resolver.NormalizeReaderToWriter(reader, file, ResolverPreviewLimit)
	closeErr := file.Close()
	if normalizeErr != nil {
		_ = os.Remove(tmp)
		return summary, normalizeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return summary, closeErr
	}
	if err := os.Rename(tmp, destPath); err != nil {
		_ = os.Remove(tmp)
		return summary, err
	}
	return summary, nil
}

func readNormalizedResolverPage(reader io.Reader, offset, limit int) ([]string, int, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	resolvers := make([]string, 0, limit)
	total := 0
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		if total >= offset && len(resolvers) < limit {
			resolvers = append(resolvers, value)
		}
		total++
	}
	return resolvers, total, scanner.Err()
}

func clamp(value, minValue, maxValue, fallback int) int {
	if value < minValue || value > maxValue {
		return fallback
	}
	return value
}

func hasConnection(profiles []model.ConnectionProfile, id string) bool {
	return slices.ContainsFunc(profiles, func(profile model.ConnectionProfile) bool { return profile.ID == id })
}

func hasResolver(profiles []model.ResolverProfile, id string) bool {
	return slices.ContainsFunc(profiles, func(profile model.ResolverProfile) bool { return profile.ID == id })
}

func hasSettings(profiles []model.SettingsProfile, id string) bool {
	return slices.ContainsFunc(profiles, func(profile model.SettingsProfile) bool { return profile.ID == id })
}

func hasV2Ray(profiles []model.V2RayProfile, id string) bool {
	return slices.ContainsFunc(profiles, func(profile model.V2RayProfile) bool { return profile.ID == id })
}

func hasV2RaySettings(profiles []model.V2RaySettingsProfile, id string) bool {
	return slices.ContainsFunc(profiles, func(profile model.V2RaySettingsProfile) bool { return profile.ID == id })
}

package model

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var ErrCredentialsRequired = errors.New("connection details are required; open the editor and enter them again")
var publicURLPattern = regexp.MustCompile(`(?i)\b(?:https?|wss?|tls|vless|vmess|trojan|shadowsocks|ssr?|hysteria2?|hy2|anytls|wireguard|wg|socks5?)://[^\s"<>]+`)

// PublicAppState is the wire representation. Internal AppState is never used
// directly by JSON serialization: nested API results and events use this same
// boundary. Persistence deliberately uses a separate private, non-marshaling type.
type PublicAppState AppState

func (s AppState) MarshalJSON() ([]byte, error) { return json.Marshal(s.Public()) }

func PublicText(text string) string { return publicURLPattern.ReplaceAllString(text, "[redacted-url]") }

func DisplayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func PublicV2RayProfile(p V2RayProfile) V2RayProfile {
	if !p.PublicOnly {
		p.CredentialsReady = V2RayCredentialsReady(p) && strings.TrimSpace(p.Server) != ""
	}
	p.PublicOnly = true
	p.UUID, p.Password, p.Username, p.HysteriaAuth = "", "", "", ""
	p.WireGuardSecretKey, p.WireGuardPreSharedKey = "", ""
	p.OutboundSettings, p.StreamSettings, p.HTTPHeaders, p.XHTTPExtra = "", "", "", ""
	p.TransportPath, p.ServiceName, p.HysteriaMasquerade, p.RealityShortID = "", "", "", ""
	return p
}

func V2RayCredentialsReady(p V2RayProfile) bool {
	if p.CredentialRequired || p.PublicOnly {
		return false
	}
	switch p.Protocol {
	case V2RayProtocolTrojan, V2RayProtocolShadowsocks, V2RayProtocolAnyTLS:
		return strings.TrimSpace(p.Password) != ""
	case V2RayProtocolHysteria2:
		return strings.TrimSpace(p.HysteriaAuth) != ""
	case V2RayProtocolWireGuard:
		return strings.TrimSpace(p.WireGuardSecretKey) != "" && strings.TrimSpace(p.WireGuardPeerPublicKey) != ""
	case V2RayProtocolSOCKS, V2RayProtocolHTTP:
		return true
	default:
		return strings.TrimSpace(p.UUID) != ""
	}
}

func PublicSubscription(s V2RaySubscription) V2RaySubscription {
	if !s.PublicOnly {
		s.DisplayURL = DisplayURL(s.URL)
	}
	s.URL = ""
	s.PublicOnly = true
	s.LastError = PublicText(s.LastError)
	return s
}

func PublicWhiteVPNSettings(s WhiteVPNSettings) WhiteVPNSettings {
	s = CloneWhiteVPNSettings(s)
	s.PublicOnly = true
	// Known built-in endpoints contain no per-user token. Custom endpoints may
	// carry credentials in userinfo, query or path, so none of their full URL is public.
	if s.DNSPrivacy.DoHURL != DefaultDoHURL {
		s.DNSPrivacy.DoHURL = ""
	}
	if s.DNSPrivacy.DoTEndpoint != DefaultDoTEndpoint {
		s.DNSPrivacy.DoTEndpoint = ""
	}
	return s
}

func (s AppState) Public() PublicAppState {
	p := PublicAppState(s)
	p.ResolverProfiles = append([]ResolverProfile(nil), s.ResolverProfiles...)
	for i := range p.ResolverProfiles {
		p.ResolverProfiles[i].ResolverPreview = append([]string(nil), p.ResolverProfiles[i].ResolverPreview...)
	}
	p.V2RaySettingsProfiles = append([]V2RaySettingsProfile(nil), s.V2RaySettingsProfiles...)
	p.WhiteDNSVPNFrontingIPs = append([]string(nil), s.WhiteDNSVPNFrontingIPs...)
	p.HiddenNodes = make(map[string][]string, len(s.HiddenNodes))
	for id, names := range s.HiddenNodes {
		p.HiddenNodes[id] = append([]string(nil), names...)
	}
	p.ConnectionProfiles = append([]ConnectionProfile(nil), s.ConnectionProfiles...)
	for i := range p.ConnectionProfiles {
		p.ConnectionProfiles[i].EncryptionKey = ""
		p.ConnectionProfiles[i].PublicOnly = true
	}
	p.SettingsProfiles = append([]SettingsProfile(nil), s.SettingsProfiles...)
	for i := range p.SettingsProfiles {
		p.SettingsProfiles[i].SOCKSUsername, p.SettingsProfiles[i].SOCKSPassword = "", ""
		p.SettingsProfiles[i].PublicOnly = true
	}
	p.V2RayProfiles = make([]V2RayProfile, len(s.V2RayProfiles))
	for i, profile := range s.V2RayProfiles {
		p.V2RayProfiles[i] = PublicV2RayProfile(profile)
	}
	p.V2RaySubscriptions = make([]V2RaySubscription, len(s.V2RaySubscriptions))
	for i, sub := range s.V2RaySubscriptions {
		p.V2RaySubscriptions[i] = PublicSubscription(sub)
	}
	p.WhiteVPN = PublicWhiteVPNSettings(s.WhiteVPN)
	// Runtime bodies are emitted separately too; the public text guard covers URLs
	// in their messages/logs without altering the internal runtime snapshot.
	p.Runtime = PublicRuntime(s.Runtime)
	return p
}

func PublicRuntime(r RuntimeStatus) RuntimeStatus {
	r.Message, r.TrafficMonitorMessage = PublicText(r.Message), PublicText(r.TrafficMonitorMessage)
	r.Logs, r.MasterDNSLogs, r.V2RayLogs = publicLogs(r.Logs), publicLogs(r.MasterDNSLogs), publicLogs(r.V2RayLogs)
	r.ResolverState.ActiveResolvers = append([]string(nil), r.ResolverState.ActiveResolvers...)
	r.ResolverState.StandbyResolvers = append([]string(nil), r.ResolverState.StandbyResolvers...)
	r.ResolverState.ValidResolvers = append([]string(nil), r.ResolverState.ValidResolvers...)
	r.ResolverState.ResolverDetails = append([]ResolverRuntimeDetail(nil), r.ResolverState.ResolverDetails...)
	for i := range r.ResolverState.ResolverDetails {
		r.ResolverState.ResolverDetails[i].Cause = PublicText(r.ResolverState.ResolverDetails[i].Cause)
		r.ResolverState.ResolverDetails[i].LastEvent = PublicText(r.ResolverState.ResolverDetails[i].LastEvent)
	}
	return r
}

func publicLogs(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = PublicText(line)
	}
	return out
}

// BackupState omits credentials and raw config while preserving explicit
// placeholders. Importers must not turn missing details into connection defaults.
func (s AppState) BackupState() AppState {
	b := AppState(s.Public())
	b.Runtime = DefaultAppState().Runtime
	for i, original := range s.ConnectionProfiles {
		b.ConnectionProfiles[i].CredentialRequired = original.CredentialRequired || original.EncryptionKey != ""
		b.ConnectionProfiles[i].PublicOnly = false
	}
	for i, original := range s.SettingsProfiles {
		b.SettingsProfiles[i].CredentialRequired = original.CredentialRequired || original.SOCKSUsername != "" || original.SOCKSPassword != ""
		b.SettingsProfiles[i].PublicOnly = false
	}
	for i, original := range s.V2RayProfiles {
		redacted := PublicV2RayProfile(original)
		// Any omitted connection material requires explicit repair, including
		// authenticated SOCKS/HTTP and raw transport configurations.
		b.V2RayProfiles[i].CredentialRequired = original.CredentialRequired || !V2RayCredentialsReady(original) ||
			original.UUID != redacted.UUID || original.Password != redacted.Password || original.Username != redacted.Username || original.HysteriaAuth != redacted.HysteriaAuth ||
			original.WireGuardSecretKey != redacted.WireGuardSecretKey || original.WireGuardPreSharedKey != redacted.WireGuardPreSharedKey ||
			original.OutboundSettings != redacted.OutboundSettings || original.StreamSettings != redacted.StreamSettings || original.HTTPHeaders != redacted.HTTPHeaders ||
			original.XHTTPExtra != redacted.XHTTPExtra || original.TransportPath != redacted.TransportPath || original.ServiceName != redacted.ServiceName || original.HysteriaMasquerade != redacted.HysteriaMasquerade || original.RealityShortID != redacted.RealityShortID
		b.V2RayProfiles[i].PublicOnly, b.V2RayProfiles[i].CredentialsReady = false, false
	}
	for i, sub := range s.V2RaySubscriptions {
		b.V2RaySubscriptions[i].CredentialRequired = sub.CredentialRequired || (!IsBuiltInSubscription(sub.ID) && !IsEverySubscription(sub.ID))
		b.V2RaySubscriptions[i].PublicOnly = false
		b.V2RaySubscriptions[i].LastError = ""
	}
	b.WhiteVPN.PublicOnly = false
	b.WhiteVPN.DNSPrivacy.CredentialRequired = s.WhiteVPN.DNSPrivacy.CredentialRequired || s.WhiteVPN.DNSPrivacy.DoHURL != b.WhiteVPN.DNSPrivacy.DoHURL || s.WhiteVPN.DNSPrivacy.DoTEndpoint != b.WhiteVPN.DNSPrivacy.DoTEndpoint
	return b
}

func CloneWhiteVPNSettings(s WhiteVPNSettings) WhiteVPNSettings {
	// These arrays are required by the UI wire contract, including when empty.
	// Cloning onto nil would serialize [] as null and break dashboard controls.
	s.Connection.Types = append([]string{}, s.Connection.Types...)
	s.SplitTunnel.Processes = append([]string{}, s.SplitTunnel.Processes...)
	s.FrontingIPs = append([]string{}, s.FrontingIPs...)
	s.DirectRouting.Domains = append([]string{}, s.DirectRouting.Domains...)
	s.DirectRouting.IPs = append([]string{}, s.DirectRouting.IPs...)
	parked := make(map[string]SubscriptionSelection, len(s.SubscriptionSelections))
	for id, entry := range s.SubscriptionSelections {
		entry.Connection.Types = append([]string{}, entry.Connection.Types...)
		parked[id] = entry
	}
	s.SubscriptionSelections = parked
	return s
}

func (r V2RaySubscriptionRefreshResult) MarshalJSON() ([]byte, error) {
	type result V2RaySubscriptionRefreshResult
	p := result(r)
	p.Subscription = PublicSubscription(r.Subscription)
	p.Message = PublicText(r.Message)
	return json.Marshal(p)
}

// Share links belong only to the explicit export response, never node lists or
// measurement events. Internal nodes retain their link for engine/cache use.
func (n WhiteVPNNode) MarshalJSON() ([]byte, error) {
	type node WhiteVPNNode
	p := node(n)
	p.Link = ""
	p.ReachError, p.DelayError, p.SpeedError = PublicText(p.ReachError), PublicText(p.DelayError), PublicText(p.SpeedError)
	return json.Marshal(struct {
		node
		ShareAvailable bool `json:"shareAvailable"`
	}{p, n.Link != "" && !n.CredentialRequired})
}

func (r RuntimeStatus) MarshalJSON() ([]byte, error) {
	type runtime RuntimeStatus
	return json.Marshal(runtime(PublicRuntime(r)))
}

func (r RuntimeLogEntry) MarshalJSON() ([]byte, error) {
	type entry RuntimeLogEntry
	p := entry(r)
	p.Line = PublicText(p.Line)
	return json.Marshal(p)
}

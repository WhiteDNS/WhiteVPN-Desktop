package model

import (
	"encoding/json"
	"strings"
)

// The settings WhiteVPN for Android exposes, so that someone moving from the
// phone finds the same options here under the same names and with the same
// defaults. Every field below corresponds to a key in ANDROID-PARITY.md; keep
// the two in step.
//
// The phone stores these across a dozen SharedPreferences files. One struct is
// enough here, and it rides along in AppState so it is backed up and restored
// with everything else.

// DNS privacy modes, matching `white_dns_privacy/mode`.
const (
	DNSPrivacyAutomatic = "automatic"
	DNSPrivacyDoH       = "doh"
	DNSPrivacyDoT       = "dot"
)

// Split tunnel modes, matching `white_dns_split_tunnel/mode`.
//
// The phone selects Android packages. Windows has no equivalent, so the same
// three modes select executables instead — see SplitTunnelSettings.Processes.
const (
	SplitTunnelOff         = "off"
	SplitTunnelBypass      = "bypass_selected"
	SplitTunnelVPNOnly     = "vpn_only_selected"
	DefaultDoHURL          = "https://1.1.1.1/dns-query"
	DefaultDoTEndpoint     = "tls://1.1.1.1:853"
	DefaultNoiseCount      = 5
	DefaultNoiseMinSize    = 50
	DefaultNoiseMaxSize    = 100
	MinNoiseCount          = 1
	MaxNoiseCount          = 20
	MinNoiseSize           = 1
	MaxNoiseSize           = 1280
	MaxFrontingIPs         = 5
	CurrentPrivacyPolicyID = 1
)

// AmneziaNoiseSettings is the WARP/Amnezia obfuscation noise.
type AmneziaNoiseSettings struct {
	Enabled bool `json:"enabled"`
	Count   int  `json:"count"`
	MinSize int  `json:"minSize"`
	MaxSize int  `json:"maxSize"`
}

// DNSPrivacySettings is the encrypted-DNS choice.
type DNSPrivacySettings struct {
	Mode        string `json:"mode"`
	DoHURL      string `json:"dohUrl"`
	DoTEndpoint string `json:"dotEndpoint"`
}

// ConnectionSelection is the dashboard's node choice: which node to connect
// through, of which protocols, and how the list is ordered while choosing.
//
// The phone keys each of these by subscription — `profile:<subId>`,
// `types:<subId>`, `delay-sort:<subId>`. There is one subscription here, the
// built-in catalogue, so they are stored flat; they become per-subscription
// when user subscriptions arrive.
type ConnectionSelection struct {
	// Node is the exact proxy name to connect through. Empty means automatic:
	// whichever node passes the filters first, in catalogue order.
	Node string `json:"node"`
	// Types restricts the choice to these protocols. Empty means all of them.
	Types []string `json:"types"`
	// DelaySort orders the connection dialog by measured delay. It is a view
	// setting and nothing more: the connect path never waits on a measurement,
	// because a node that fails a delay probe can still carry traffic.
	DelaySort bool `json:"delaySort"`
}

// SplitTunnelSettings routes some programs around the tunnel, or only some
// through it.
type SplitTunnelSettings struct {
	Mode string `json:"mode"`
	// Processes are executable names, because that is what mihomo's
	// `process-name` rules match on Windows. Matching is by file name, so two
	// programs installed under the same executable name cannot be told apart —
	// the UI has to say so rather than let a user discover it.
	Processes []string `json:"processes"`
}

// KillSwitchSettings blocks traffic that would otherwise leave outside the
// tunnel.
//
// This one is more than a port. Android does not implement a kill switch at all:
// the OS provides always-on/lockdown and the app only reports its state. Windows
// has no equivalent, so the app has to enforce it, which also means it has to
// remove the block on a clean exit, after a crash, and on uninstall — a rule
// that outlives the app leaves a user with no internet and no visible cause.
type KillSwitchSettings struct {
	Enabled bool `json:"enabled"`
}

// WhiteVPNSettings is everything the phone lets a user change.
type WhiteVPNSettings struct {
	// Dashboard rows.
	CountryCode string              `json:"countryCode"`
	Connection  ConnectionSelection `json:"connection"`
	SplitTunnel SplitTunnelSettings `json:"splitTunnel"`

	// Settings sections, in the order the phone shows them.
	TLSIntegrityEnabled bool                 `json:"tlsIntegrityEnabled"`
	AmneziaNoise        AmneziaNoiseSettings `json:"amneziaNoise"`
	FrontingIPs         []string             `json:"frontingIps"`
	DNSPrivacy          DNSPrivacySettings   `json:"dnsPrivacy"`
	KillSwitch          KillSwitchSettings   `json:"killSwitch"`

	// Appearance. The phone defaults to Persian; this defaults to the system
	// language, because a desktop user who installed an English build and is
	// shown Persian will assume the app is broken.
	Language string `json:"language"`

	// Tunnel. Not a phone setting: there, VpnService always provides the tunnel.
	// Here it can be turned off, and off is the only mode that works without
	// Administrator.
	TunEnabled bool `json:"tunEnabled"`

	// SetSystemProxy points the machine's proxy settings at the engine when the
	// tunnel is off.
	//
	// Neither this nor the tunnel leaves a third option: with both off the
	// engine listens and nothing on the machine is redirected, which is what
	// somebody wants who is pointing one browser extension or Telegram at it and
	// leaving everything else alone. Until this existed, turning the tunnel off
	// silently reconfigured the whole desktop and there was no way to ask for
	// anything else.
	//
	// There is a SetSystemProxy on V2RaySettingsProfile too. That one belongs to
	// the removed Xray path and nothing reads it.
	SetSystemProxy bool `json:"setSystemProxy"`

	// AllowLAN opens the local proxy to the rest of the network rather than to
	// this machine alone, so another device — a phone on the same hotspot, a
	// television — can use this desktop's connection.
	//
	// Off by default and deliberately not remembered as a general preference the
	// way the others are: nothing authenticates a client, so whoever else is on
	// that network can use the tunnel too. On a hotspot the user owns that is the
	// point; on a café's wifi it is a stranger's free VPN.
	AllowLAN bool `json:"allowLan"`

	// ListenPort is where the engine's local proxy listens, serving HTTP and
	// SOCKS5 on the one port.
	//
	// Settable because in proxy-only mode this number is not an implementation
	// detail — it is what the user typed into another program, and it has to
	// keep working tomorrow.
	ListenPort int `json:"listenPort"`

	AcceptedPrivacyPolicyVersion int `json:"acceptedPrivacyPolicyVersion"`
}

// DefaultWhiteVPNSettings mirrors the phone's defaults.
func DefaultWhiteVPNSettings() WhiteVPNSettings {
	return WhiteVPNSettings{
		CountryCode:         "", // unset means automatic
		Connection:          ConnectionSelection{Node: "", Types: []string{}, DelaySort: false},
		SplitTunnel:         SplitTunnelSettings{Mode: SplitTunnelOff, Processes: []string{}},
		TLSIntegrityEnabled: false,
		AmneziaNoise: AmneziaNoiseSettings{
			Enabled: false,
			Count:   DefaultNoiseCount,
			MinSize: DefaultNoiseMinSize,
			MaxSize: DefaultNoiseMaxSize,
		},
		FrontingIPs: []string{},
		DNSPrivacy: DNSPrivacySettings{
			Mode:        DNSPrivacyAutomatic,
			DoHURL:      DefaultDoHURL,
			DoTEndpoint: DefaultDoTEndpoint,
		},
		KillSwitch: KillSwitchSettings{Enabled: false},
		Language:   "",
		TunEnabled: false,
		// On by default, because that is what the app did before this was a
		// choice, and an update that silently stopped proxying a machine would
		// look exactly like an update that broke the connection.
		SetSystemProxy: true,
		ListenPort:     DefaultLocalProxyPort,
	}
}

// DefaultLocalProxyPort is the engine's usual mixed port — HTTP and SOCKS5 on
// one listener.
const DefaultLocalProxyPort = 2080

// UnmarshalJSON reads settings, treating an absent SetSystemProxy as on.
//
// Every settings file written before that field existed has no key for it, and
// a plain bool reads a missing key as false — which is the new proxy-only mode.
// Everyone who updated would have found their machine quietly no longer
// proxied, which looks exactly like an update that broke the connection, and
// nothing in the app would have said otherwise.
//
// The distinction only survives at this boundary. By the time the value is a
// bool, "absent" and "deliberately off" are the same thing, so no migration
// running later could tell them apart.
func (s *WhiteVPNSettings) UnmarshalJSON(data []byte) error {
	// An alias to borrow the generated decoding without recursing into this
	// method. The pointer field sits shallower than the embedded struct's, so
	// encoding/json fills this one and leaves that one alone.
	type alias WhiteVPNSettings
	probe := struct {
		*alias
		SetSystemProxy *bool `json:"setSystemProxy"`
	}{alias: (*alias)(s)}

	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	s.SetSystemProxy = probe.SetSystemProxy == nil || *probe.SetSystemProxy
	return nil
}

// NormalizeWhiteVPNSettings repairs a settings block read from disk.
//
// Anything out of range is replaced with the default rather than clamped: a
// value a user never chose is better than one silently bent into shape, and a
// clamped noise size looks like the app ignoring what was typed.
func NormalizeWhiteVPNSettings(settings WhiteVPNSettings) WhiteVPNSettings {
	defaults := DefaultWhiteVPNSettings()

	switch settings.SplitTunnel.Mode {
	case SplitTunnelOff, SplitTunnelBypass, SplitTunnelVPNOnly:
	default:
		settings.SplitTunnel.Mode = SplitTunnelOff
	}
	settings.SplitTunnel.Processes = nonEmptyStrings(settings.SplitTunnel.Processes)
	// Selecting nothing in VPN-only mode would route no traffic at all, which
	// looks exactly like a broken tunnel.
	if settings.SplitTunnel.Mode == SplitTunnelVPNOnly && len(settings.SplitTunnel.Processes) == 0 {
		settings.SplitTunnel.Mode = SplitTunnelOff
	}

	if settings.AmneziaNoise.Count < MinNoiseCount || settings.AmneziaNoise.Count > MaxNoiseCount {
		settings.AmneziaNoise.Count = defaults.AmneziaNoise.Count
	}
	if settings.AmneziaNoise.MinSize < MinNoiseSize || settings.AmneziaNoise.MinSize > MaxNoiseSize {
		settings.AmneziaNoise.MinSize = defaults.AmneziaNoise.MinSize
	}
	if settings.AmneziaNoise.MaxSize < MinNoiseSize || settings.AmneziaNoise.MaxSize > MaxNoiseSize {
		settings.AmneziaNoise.MaxSize = defaults.AmneziaNoise.MaxSize
	}
	if settings.AmneziaNoise.MinSize > settings.AmneziaNoise.MaxSize {
		settings.AmneziaNoise.MinSize, settings.AmneziaNoise.MaxSize = defaults.AmneziaNoise.MinSize, defaults.AmneziaNoise.MaxSize
	}

	settings.FrontingIPs = nonEmptyStrings(settings.FrontingIPs)
	if len(settings.FrontingIPs) > MaxFrontingIPs {
		settings.FrontingIPs = settings.FrontingIPs[:MaxFrontingIPs]
	}

	switch settings.DNSPrivacy.Mode {
	case DNSPrivacyAutomatic, DNSPrivacyDoH, DNSPrivacyDoT:
	default:
		settings.DNSPrivacy.Mode = DNSPrivacyAutomatic
	}
	if trimmed := strings.TrimSpace(settings.DNSPrivacy.DoHURL); trimmed == "" {
		settings.DNSPrivacy.DoHURL = defaults.DNSPrivacy.DoHURL
	} else {
		settings.DNSPrivacy.DoHURL = trimmed
	}
	if trimmed := strings.TrimSpace(settings.DNSPrivacy.DoTEndpoint); trimmed == "" {
		settings.DNSPrivacy.DoTEndpoint = defaults.DNSPrivacy.DoTEndpoint
	} else {
		settings.DNSPrivacy.DoTEndpoint = trimmed
	}

	settings.CountryCode = NormalizeCountryCode(settings.CountryCode)
	settings.Connection.Node = strings.TrimSpace(settings.Connection.Node)
	settings.Connection.Types = nonEmptyStrings(lowered(settings.Connection.Types))
	settings.Language = strings.TrimSpace(settings.Language)

	// A port outside the range, or one of the reserved low ones no ordinary
	// program may bind, becomes the default rather than reaching the engine and
	// failing there where the cause is much harder to see. Zero included: that
	// is what a settings block written before this field existed carries, and it
	// must read as "the usual port", not as "let the system choose".
	if settings.ListenPort < 1024 || settings.ListenPort > 65535 {
		settings.ListenPort = defaults.ListenPort
	}
	return settings
}

// NormalizeCountryCode settles on the shape the catalogue's own names yield:
// two upper-case letters, or empty for anywhere. Anything else is a value no
// node can match, and a filter that matches nothing looks exactly like an
// empty catalogue.
func NormalizeCountryCode(value string) string {
	code := strings.ToUpper(strings.TrimSpace(value))
	if len(code) != 2 {
		return ""
	}
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return code
}

func lowered(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	return out
}

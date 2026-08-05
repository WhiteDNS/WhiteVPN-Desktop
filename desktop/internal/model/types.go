package model

import (
	"runtime"
	"strings"
	"time"
)

const (
	RuntimeDisconnected = "disconnected"
	RuntimeConnecting   = "connecting"
	RuntimeConnected    = "connected"
	// RuntimeStopping is the time between asking to disconnect and being
	// disconnected. Killing the engine and removing its tunnel adapter takes
	// long enough to be seen, and without a status of its own the interface has
	// nothing to show for it but a button that appears not to have worked.
	RuntimeStopping = "stopping"
	RuntimeFailed   = "failed"

	RuntimeTypeMasterDNS = "masterdns"
	RuntimeTypeV2Ray     = "v2ray"

	ScannerIdle      = "idle"
	ScannerRunning   = "running"
	ScannerCancelled = "cancelled"
	ScannerCompleted = "completed"
	ScannerFailed    = "failed"

	ValidatorIdle      = ScannerIdle
	ValidatorRunning   = ScannerRunning
	ValidatorCancelled = ScannerCancelled
	ValidatorCompleted = ScannerCompleted
	ValidatorFailed    = ScannerFailed

	ParallelTestIdle      = "idle"
	ParallelTestRunning   = "running"
	ParallelTestCancelled = "cancelled"
	ParallelTestCompleted = "completed"
	ParallelTestFailed    = "failed"

	// BuiltInSubscriptionID names the catalogue the app ships with. It is the
	// one subscription whose address is not stored — the app holds it as a
	// constant — so it is also the one that may sit in the list without one.
	BuiltInSubscriptionID = "whitedns-vpn"

	DefaultConnectionProfileID = "default"
	DefaultResolverProfileID   = "resolver-default"
	DefaultSettingsProfileID   = "settings-default"
	DefaultV2RayProfileID      = "v2ray-default"
	DefaultV2RaySettingsID     = "v2ray-settings-default"

	ImportTypeMasterDNS = "masterdns"
	ImportTypeStormDNS  = "stormdns"

	V2RayProtocolVLESS       = "vless"
	V2RayProtocolVMess       = "vmess"
	V2RayProtocolTrojan      = "trojan"
	V2RayProtocolShadowsocks = "shadowsocks"
	V2RayProtocolHysteria2   = "hysteria2"
	V2RayProtocolWireGuard   = "wireguard"
	V2RayProtocolSOCKS       = "socks"
	V2RayProtocolHTTP        = "http"

	ConnectionStartupModeStandard = "standard"
	ConnectionStartupModeFullScan = "full-scan"
)

type Choice[T comparable] struct {
	Value T      `json:"value"`
	Label string `json:"label"`
}

func NormalizeImportType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ImportTypeStormDNS:
		return ImportTypeStormDNS
	default:
		return ImportTypeMasterDNS
	}
}

type ConnectionProfile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	ImportType        string `json:"importType"`
	Domain            string `json:"domain"`
	EncryptionKey     string `json:"encryptionKey"`
	EncryptionMethod  int    `json:"encryptionMethod"`
	ResolverProfileID string `json:"resolverProfileId"`
}

type ResolverProfile struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	ResolverText         string   `json:"resolverText"`
	ResolverSource       string   `json:"resolverSource"`
	ResolverFile         string   `json:"resolverFile"`
	ResolverCount        int      `json:"resolverCount"`
	ResolverPreview      []string `json:"resolverPreview"`
	ResolverInvalidCount int      `json:"resolverInvalidCount"`
}

type V2RayProfile struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	SubscriptionID           string `json:"subscriptionId"`
	Protocol                 string `json:"protocol"`
	Server                   string `json:"server"`
	ServerPort               int    `json:"serverPort"`
	UUID                     string `json:"uuid"`
	Password                 string `json:"password"`
	AlterID                  int    `json:"alterId"`
	Security                 string `json:"security"`
	Flow                     string `json:"flow"`
	PacketEncoding           string `json:"packetEncoding"`
	Network                  string `json:"network"`
	TLS                      bool   `json:"tls"`
	SNI                      string `json:"sni"`
	ALPN                     string `json:"alpn"`
	AllowInsecure            bool   `json:"allowInsecure"`
	UTLSFingerprint          string `json:"utlsFingerprint"`
	ECHConfigList            string `json:"echConfigList"`
	Reality                  bool   `json:"reality"`
	RealityPublicKey         string `json:"realityPublicKey"`
	RealityShortID           string `json:"realityShortId"`
	TransportPath            string `json:"transportPath"`
	TransportHost            string `json:"transportHost"`
	ServiceName              string `json:"serviceName"`
	XHTTPMode                string `json:"xhttpMode"`
	XHTTPExtra               string `json:"xhttpExtra"`
	WebSocketEarlyData       int    `json:"webSocketEarlyData"`
	WebSocketEarlyDataHeader string `json:"webSocketEarlyDataHeader"`
	Username                 string `json:"username"`
	ShadowsocksMethod        string `json:"shadowsocksMethod"`
	UoT                      bool   `json:"uot"`
	UoTVersion               int    `json:"uotVersion"`
	HysteriaAuth             string `json:"hysteriaAuth"`
	HysteriaUDPIdleTimeout   int    `json:"hysteriaUdpIdleTimeout"`
	HysteriaMasquerade       string `json:"hysteriaMasquerade"`
	HTTPHeaders              string `json:"httpHeaders"`
	WireGuardSecretKey       string `json:"wireGuardSecretKey"`
	WireGuardLocalAddresses  string `json:"wireGuardLocalAddresses"`
	WireGuardPeerPublicKey   string `json:"wireGuardPeerPublicKey"`
	WireGuardPreSharedKey    string `json:"wireGuardPreSharedKey"`
	WireGuardAllowedIPs      string `json:"wireGuardAllowedIps"`
	WireGuardKeepAlive       int    `json:"wireGuardKeepAlive"`
	WireGuardMTU             int    `json:"wireGuardMtu"`
	WireGuardReserved        string `json:"wireGuardReserved"`
	WireGuardNoKernelTun     bool   `json:"wireGuardNoKernelTun"`
	WireGuardDomainStrategy  string `json:"wireGuardDomainStrategy"`
	OutboundSettings         string `json:"outboundSettings"`
	StreamSettings           string `json:"streamSettings"`
}

type V2RaySettingsProfile struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	ListenIP           string `json:"listenIp"`
	AllowLAN           bool   `json:"allowLan"`
	ListenPort         int    `json:"listenPort"`
	InboundType        string `json:"inboundType"`
	SetSystemProxy     bool   `json:"setSystemProxy"`
	TunEnabled         bool   `json:"tunEnabled"`
	TunMTU             int    `json:"tunMtu"`
	TunIPv6            bool   `json:"tunIpv6"`
	TunInterfaceName   string `json:"tunInterfaceName"`
	IranRoutingEnabled bool   `json:"iranRoutingEnabled"`
	LogLevel           string `json:"logLevel"`
}

type V2RaySubscription struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	LastUpdatedAt string `json:"lastUpdatedAt"`
	LastError     string `json:"lastError"`
	ImportedCount int    `json:"importedCount"`
}

type V2RayPingResult struct {
	ProfileID              string `json:"profileId"`
	Endpoint               string `json:"endpoint"`
	OK                     bool   `json:"ok"`
	LatencyMs              int64  `json:"latencyMs"`
	Message                string `json:"message"`
	DownloadBytesPerSecond int64  `json:"downloadBytesPerSecond"`
	SpeedTestBytes         int64  `json:"speedTestBytes"`
	SpeedTestDurationMs    int64  `json:"speedTestDurationMs"`
	SpeedOK                bool   `json:"speedOk"`
	RealDelayMs            int64  `json:"realDelayMs"`
	DelayOK                bool   `json:"delayOk"`
	SpeedMessage           string `json:"speedMessage"`
	DelayMessage           string `json:"delayMessage"`
}

type V2RayDuplicateRemovalResult struct {
	State   AppState `json:"state"`
	Removed int      `json:"removed"`
}

type SettingsProfile struct {
	ID                               string  `json:"id"`
	Name                             string  `json:"name"`
	ImportType                       string  `json:"importType"`
	ListenIP                         string  `json:"listenIp"`
	ListenPort                       int     `json:"listenPort"`
	SOCKS5Authentication             bool    `json:"socks5Authentication"`
	SOCKSUsername                    string  `json:"socksUsername"`
	SOCKSPassword                    string  `json:"socksPassword"`
	SingBoxEnabled                   bool    `json:"singBoxEnabled"`
	SingBoxInboundType               string  `json:"singBoxInboundType"`
	SingBoxSetSystemProxy            bool    `json:"singBoxSetSystemProxy"`
	StormDNSListenIP                 string  `json:"stormDnsListenIp"`
	StormDNSListenPort               int     `json:"stormDnsListenPort"`
	LocalDNSEnabled                  bool    `json:"localDnsEnabled"`
	LocalDNSPort                     int     `json:"localDnsPort"`
	BalancingStrategy                int     `json:"balancingStrategy"`
	UploadDuplication                int     `json:"uploadDuplication"`
	DownloadDuplication              int     `json:"downloadDuplication"`
	AutoRemoveLowMTUServers          bool    `json:"autoRemoveLowMtuServers"`
	SaveMTUServersToFile             bool    `json:"saveMtuServersToFile"`
	MTUServersFileName               string  `json:"mtuServersFileName"`
	MTUServersFileFormat             string  `json:"mtuServersFileFormat"`
	MTUUsingSectionSeparatorText     string  `json:"mtuUsingSectionSeparatorText"`
	MTURemovedServerLogFormat        string  `json:"mtuRemovedServerLogFormat"`
	MTUAddedServerLogFormat          string  `json:"mtuAddedServerLogFormat"`
	MTUReactiveAddedServerLogFormat  string  `json:"mtuReactiveAddedServerLogFormat"`
	UploadCompression                int     `json:"uploadCompression"`
	DownloadCompression              int     `json:"downloadCompression"`
	BaseEncodeData                   bool    `json:"baseEncodeData"`
	MinUploadMTU                     int     `json:"minUploadMtu"`
	MinDownloadMTU                   int     `json:"minDownloadMtu"`
	MaxUploadMTU                     int     `json:"maxUploadMtu"`
	MaxDownloadMTU                   int     `json:"maxDownloadMtu"`
	MTUTestRetriesResolvers          int     `json:"mtuTestRetriesResolvers"`
	MTUTestTimeoutResolvers          float64 `json:"mtuTestTimeoutResolvers"`
	MTUTestParallelismResolvers      int     `json:"mtuTestParallelismResolvers"`
	MTUStartupLossVerifyEnabled      bool    `json:"mtuStartupLossVerifyEnabled"`
	MTUStartupLossVerifySamples      int     `json:"mtuStartupLossVerifySamples"`
	MTUStartupLossVerifyMaxLossPct   int     `json:"mtuStartupLossVerifyMaxLossPercent"`
	MTUStartupLossVerifyCandidates   int     `json:"mtuStartupLossVerifyCandidates"`
	MTURecheckEnabled                bool    `json:"mtuRecheckEnabled"`
	MTURecheckIntervalMinutes        int     `json:"mtuRecheckIntervalMinutes"`
	MTUTestRetriesLogs               int     `json:"mtuTestRetriesLogs"`
	MTUTestTimeoutLogs               float64 `json:"mtuTestTimeoutLogs"`
	MTUTestParallelismLogs           int     `json:"mtuTestParallelismLogs"`
	ConnectionStartupMode            string  `json:"connectionStartupMode"`
	RXTXWorkers                      int     `json:"rxTxWorkers"`
	TunnelProcessWorkers             int     `json:"tunnelProcessWorkers"`
	TunnelPacketTimeoutSeconds       float64 `json:"tunnelPacketTimeoutSeconds"`
	DispatcherIdlePollIntervalSec    float64 `json:"dispatcherIdlePollIntervalSeconds"`
	TXChannelSize                    int     `json:"txChannelSize"`
	RXChannelSize                    int     `json:"rxChannelSize"`
	ResolverUDPConnectionPoolSize    int     `json:"resolverUdpConnectionPoolSize"`
	StreamQueueInitialCapacity       int     `json:"streamQueueInitialCapacity"`
	OrphanQueueInitialCapacity       int     `json:"orphanQueueInitialCapacity"`
	DNSResponseFragmentStoreCapacity int     `json:"dnsResponseFragmentStoreCapacity"`
	MaxActiveStreams                 int     `json:"maxActiveStreams"`
	LocalHandshakeTimeoutSeconds     float64 `json:"localHandshakeTimeoutSeconds"`
	SOCKSUDPAssociateReadTimeoutSec  float64 `json:"socksUdpAssociateReadTimeoutSeconds"`
	ClientTerminalStreamRetentionSec float64 `json:"clientTerminalStreamRetentionSeconds"`
	ClientCancelledSetupRetentionSec float64 `json:"clientCancelledSetupRetentionSeconds"`
	SessionInitRetryBaseSeconds      float64 `json:"sessionInitRetryBaseSeconds"`
	SessionInitRetryStepSeconds      float64 `json:"sessionInitRetryStepSeconds"`
	SessionInitRetryLinearAfter      int     `json:"sessionInitRetryLinearAfter"`
	SessionInitRetryMaxSeconds       float64 `json:"sessionInitRetryMaxSeconds"`
	SessionInitBusyRetryIntervalSec  float64 `json:"sessionInitBusyRetryIntervalSeconds"`
	SessionInitRacingCount           int     `json:"sessionInitRacingCount"`
	StartupMode                      string  `json:"startupMode"`
	PingWatchdogSeconds              int     `json:"pingWatchdogSeconds"`
	LogLevel                         string  `json:"logLevel"`
}

type RuntimeStatus struct {
	Status string `json:"status"`
	// Engine names what is running: "mihomo" for the engine the phone app uses,
	// empty for the Xray path.
	//
	// The interface needs this because it otherwise recognises its own connection
	// by matching ActiveConnectionID against a stored V2Ray profile. A mihomo
	// session has no such profile - it connects straight from the subscription -
	// so without this the app reports its own working connection as belonging to
	// something else.
	Engine             string `json:"engine"`
	RuntimeType        string `json:"runtimeType"`
	Message            string `json:"message"`
	ActiveConnectionID string `json:"activeConnectionId"`
	ListenIP           string `json:"listenIp"`
	ListenPort         int    `json:"listenPort"`
	ProxyProtocol      string `json:"proxyProtocol"`
	LocalProxyIP       string `json:"localProxyIp"`
	PublicProxyIP      string `json:"publicProxyIp"`
	FrontingIP         string `json:"frontingIp"`

	// The node carrying traffic, and where it says it is: the name the catalogue
	// gave it, and the country from the flag in that name.
	NodeName        string `json:"nodeName"`
	NodeCountryCode string `json:"nodeCountryCode"`
	// ExitIP is the address the internet sees traffic coming from, measured
	// through the proxy. It is not PublicProxyIP, which is where this machine's
	// own proxy can be reached on the LAN — writing one into the other makes the
	// app claim its local proxy listens on a remote address.
	ExitIP string `json:"exitIp"`
	// ExitCountryCode is where traffic is measured to actually leave from — the
	// country of ExitIP, resolved through the proxy itself. It is kept
	// apart from NodeCountryCode deliberately: the two can disagree, and when
	// they do, the measured one is the one that is true.
	ExitCountryCode string `json:"exitCountryCode"`
	// ExitChecked says the measurement has been attempted, so an attempt that
	// found nothing can be told from one still running. Without it a failed
	// lookup leaves a spinner turning over work that stopped.
	ExitChecked bool `json:"exitChecked"`

	ResolverMTUScanPaused bool                 `json:"resolverMtuScanPaused"`
	AutoProfilePresetID   string               `json:"autoProfilePresetId"`
	AutoProfileName       string               `json:"autoProfileName"`
	Progress              ConnectionProgress   `json:"progress"`
	ResolverState         ResolverRuntimeState `json:"resolverState"`
	Stats                 TrafficStats         `json:"stats"`
	TrafficMonitorMessage string               `json:"trafficMonitorMessage"`
	Logs                  []string             `json:"logs"`
	MasterDNSLogs         []string             `json:"masterDnsLogs"`
	V2RayLogs             []string             `json:"v2rayLogs"`
}

type RuntimeLogEntry struct {
	RuntimeType string `json:"runtimeType"`
	Line        string `json:"line"`
}

type FirewallStatus struct {
	Enabled   bool   `json:"enabled"`
	Supported bool   `json:"supported"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

type AppState struct {
	SelectedConnectionProfileID string `json:"selectedConnectionProfileId"`
	SelectedResolverProfileID   string `json:"selectedResolverProfileId"`
	SelectedSettingsProfileID   string `json:"selectedSettingsProfileId"`
	SelectedV2RayProfileID      string `json:"selectedV2RayProfileId"`
	SelectedV2RaySettingsID     string `json:"selectedV2RaySettingsId"`
	// SelectedSubscriptionID is the subscription the VPN connects through. It
	// defaults to the built-in catalogue and falls back to it when whatever it
	// named is gone.
	SelectedSubscriptionID string                 `json:"selectedSubscriptionId"`
	Theme                  string                 `json:"theme"`
	ConnectionProfiles     []ConnectionProfile    `json:"connectionProfiles"`
	ResolverProfiles       []ResolverProfile      `json:"resolverProfiles"`
	SettingsProfiles       []SettingsProfile      `json:"settingsProfiles"`
	V2RayProfiles          []V2RayProfile         `json:"v2rayProfiles"`
	V2RaySubscriptions     []V2RaySubscription    `json:"v2raySubscriptions"`
	V2RaySettingsProfiles  []V2RaySettingsProfile `json:"v2raySettingsProfiles"`
	WhiteDNSVPNFrontingIPs []string               `json:"whiteDNSVPNFrontingIps"`
	WhiteVPN               WhiteVPNSettings       `json:"whiteVpn"`
	Runtime                RuntimeStatus          `json:"runtime"`
}

type ConnectionImportResult struct {
	State    AppState `json:"state"`
	Imported int      `json:"imported"`
}

type ConnectionTestResolver struct {
	Endpoint       string `json:"endpoint"`
	UploadMTU      int    `json:"uploadMtu"`
	DownloadMTU    int    `json:"downloadMtu"`
	UploadMTUChars int    `json:"uploadMtuChars"`
}

type ConnectionTestResult struct {
	ProfileID string                   `json:"profileId"`
	OK        bool                     `json:"ok"`
	LatencyMs int64                    `json:"latencyMs"`
	Message   string                   `json:"message"`
	Resolver  string                   `json:"resolver"`
	Resolvers []ConnectionTestResolver `json:"resolvers"`
}

type V2RayImportResult struct {
	State    AppState `json:"state"`
	Imported int      `json:"imported"`
}

type V2RayWhiteIPImportResult struct {
	State              AppState `json:"state"`
	Imported           int      `json:"imported"`
	WhiteIPCount       int      `json:"whiteIpCount"`
	SourceProfileCount int      `json:"sourceProfileCount"`
}

type V2RayWhiteIPGenerateResult struct {
	ConfigText         string `json:"configText"`
	Generated          int    `json:"generated"`
	WhiteIPCount       int    `json:"whiteIpCount"`
	SourceProfileCount int    `json:"sourceProfileCount"`
}

type V2RaySubscriptionRefreshResult struct {
	State        AppState          `json:"state"`
	Subscription V2RaySubscription `json:"subscription"`
	OK           bool              `json:"ok"`
	Message      string            `json:"message"`
	Imported     int               `json:"imported"`
	Removed      int               `json:"removed"`
}

type ValidatorResolverProfileInput struct {
	Endpoint string `json:"endpoint"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

type ValidatorResolverProfileRequest struct {
	Results []ValidatorResolverProfileInput `json:"results"`
}

type ResolverImportResult struct {
	State    AppState        `json:"state"`
	Profile  ResolverProfile `json:"profile"`
	Imported int             `json:"imported"`
	Skipped  int             `json:"skipped"`
}

type ResolverPreviewPage struct {
	Resolvers []string `json:"resolvers"`
	Offset    int      `json:"offset"`
	Limit     int      `json:"limit"`
	Total     int      `json:"total"`
	HasMore   bool     `json:"hasMore"`
}

type ResolverTextValidation struct {
	NormalizedResolvers []string `json:"normalizedResolvers"`
	InvalidEntries      []string `json:"invalidEntries"`
	NormalizedText      string   `json:"normalizedText"`
	IsValid             bool     `json:"isValid"`
}

type ConnectionProgress struct {
	Phase     string `json:"phase"`
	Percent   int    `json:"percent"`
	Completed int    `json:"completed"`
	Total     int    `json:"total"`
	Valid     int    `json:"valid"`
	Rejected  int    `json:"rejected"`
}

type ResolverRuntimeState struct {
	ActiveResolvers  []string                `json:"activeResolvers"`
	StandbyResolvers []string                `json:"standbyResolvers"`
	ValidResolvers   []string                `json:"validResolvers"`
	ResolverDetails  []ResolverRuntimeDetail `json:"resolverDetails"`
	TotalCount       int                     `json:"totalCount"`
	ActiveCount      int                     `json:"activeCount"`
	StandbyCount     int                     `json:"standbyCount"`
	ValidCount       int                     `json:"validCount"`
	RejectedCount    int                     `json:"rejectedCount"`
	PendingCount     int                     `json:"pendingCount"`
	ActiveComplete   bool                    `json:"activeComplete"`
	StandbyComplete  bool                    `json:"standbyComplete"`
	ValidComplete    bool                    `json:"validComplete"`
}

type ResolverRuntimeDetail struct {
	Resolver       string `json:"resolver"`
	Domain         string `json:"domain"`
	Status         string `json:"status"`
	Active         bool   `json:"active"`
	Valid          bool   `json:"valid"`
	UploadMTU      int    `json:"uploadMtu"`
	DownloadMTU    int    `json:"downloadMtu"`
	UploadMTUChars int    `json:"uploadMtuChars"`
	LastEvent      string `json:"lastEvent"`
	Cause          string `json:"cause"`
}

type TrafficStats struct {
	DownloadBytes               int64 `json:"downloadBytes"`
	UploadBytes                 int64 `json:"uploadBytes"`
	DownloadSpeedBytesPerSecond int64 `json:"downloadSpeedBytesPerSecond"`
	UploadSpeedBytesPerSecond   int64 `json:"uploadSpeedBytesPerSecond"`
	TotalDataUsageBytes         int64 `json:"totalDataUsageBytes"`
}

type CloudflarePingResult struct {
	OK        bool   `json:"ok"`
	Target    string `json:"target"`
	Proxy     string `json:"proxy"`
	LatencyMs int64  `json:"latencyMs"`
	Message   string `json:"message"`
}

type ProxyCountryLookupResult struct {
	OK          bool   `json:"ok"`
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode"`
	Proxy       string `json:"proxy"`
	Message     string `json:"message"`
}

// WhiteVPNNode is one node of the catalogue, as the connection dialog shows it.
type WhiteVPNNode struct {
	// Name is the exact proxy name. It is the node's identity: what the engine
	// selects by, and what the stored choice records.
	Name string `json:"name"`
	// Label is the same name with the flag and the channel marker taken off,
	// because neither says anything the row does not already show.
	Label string `json:"label"`
	Type  string `json:"type"`
	// CountryCode is empty when the catalogue does not say where a node is.
	CountryCode string `json:"countryCode"`
	// Server and Port are where the node is reached, which the reachability
	// test needs and a person comparing nodes wants to see.
	Server string `json:"server"`
	Port   int    `json:"port"`
	// Transport and TLS say how it carries traffic.
	Transport string `json:"transport"`
	TLS       bool   `json:"tls"`
	// Link is the share link this node arrived as, which is what sharing it
	// hands back.
	Link string `json:"link"`

	// Measurements, each in one of three states rather than two: never run,
	// run and failed, run and measured. Collapsing the first two makes a node
	// that could not be reached look exactly like one nobody has tested, which
	// is the difference between "avoid this" and "find out".
	ReachTested bool `json:"reachTested"`
	ReachOK     bool `json:"reachOk"`
	ReachMs     int  `json:"reachMs"`

	DelayTested bool `json:"delayTested"`
	DelayOK     bool `json:"delayOk"`
	DelayMs     int  `json:"delayMs"`

	SpeedTested         bool  `json:"speedTested"`
	SpeedOK             bool  `json:"speedOk"`
	SpeedBytesPerSecond int64 `json:"speedBytesPerSecond"`
}

// NodeTestRequest is one run of the tests: which nodes, which tests, and the
// numbers the user is allowed to change.
type NodeTestRequest struct {
	Nodes []string `json:"nodes"`

	Reachability bool `json:"reachability"`
	Delay        bool `json:"delay"`
	Speed        bool `json:"speed"`

	ReachabilityTimeoutMs int    `json:"reachabilityTimeoutMs"`
	ReachabilityWorkers   int    `json:"reachabilityWorkers"`
	DelayTimeoutMs        int    `json:"delayTimeoutMs"`
	DelayWorkers          int    `json:"delayWorkers"`
	DelayURL              string `json:"delayUrl"`
	SpeedBudgetMs         int    `json:"speedBudgetMs"`
	SpeedURL              string `json:"speedUrl"`
}

// The bounds. Anything outside them is replaced with the default rather than
// clamped, for the same reason the settings do it: a value nobody chose beats
// one silently bent into shape.
const (
	MinTestTimeoutMs = 500
	MaxTestTimeoutMs = 60000
	MinTestWorkers   = 1
	MaxTestWorkers   = 256
)

func NormalizeNodeTestRequest(request NodeTestRequest) NodeTestRequest {
	request.Nodes = nonEmptyStrings(request.Nodes)
	if !request.Reachability && !request.Delay && !request.Speed {
		// A run with no test selected would look like a run that found nothing.
		request.Reachability = true
	}
	request.ReachabilityTimeoutMs = boundedOrDefault(request.ReachabilityTimeoutMs, MinTestTimeoutMs, MaxTestTimeoutMs, 3500)
	request.DelayTimeoutMs = boundedOrDefault(request.DelayTimeoutMs, MinTestTimeoutMs, MaxTestTimeoutMs, 5000)
	request.SpeedBudgetMs = boundedOrDefault(request.SpeedBudgetMs, MinTestTimeoutMs, MaxTestTimeoutMs, 8000)
	request.ReachabilityWorkers = boundedOrDefault(request.ReachabilityWorkers, MinTestWorkers, MaxTestWorkers, 64)
	request.DelayWorkers = boundedOrDefault(request.DelayWorkers, MinTestWorkers, MaxTestWorkers, 16)
	request.DelayURL = strings.TrimSpace(request.DelayURL)
	request.SpeedURL = strings.TrimSpace(request.SpeedURL)
	return request
}

func (r NodeTestRequest) ReachabilityTimeout() time.Duration {
	return time.Duration(r.ReachabilityTimeoutMs) * time.Millisecond
}

func (r NodeTestRequest) DelayTimeout() time.Duration {
	return time.Duration(r.DelayTimeoutMs) * time.Millisecond
}

func (r NodeTestRequest) SpeedBudget() time.Duration {
	return time.Duration(r.SpeedBudgetMs) * time.Millisecond
}

func boundedOrDefault(value, min, max, fallback int) int {
	if value < min || value > max {
		return fallback
	}
	return value
}

// WhiteVPNNodeList is the catalogue the dashboard chooses from.
type WhiteVPNNodeList struct {
	Nodes     []WhiteVPNNode `json:"nodes"`
	UpdatedAt string         `json:"updatedAt"`
}

type ValidatorEndpointInput struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

type ValidatorOptions struct {
	Retries           int      `json:"retries"`
	TimeoutMillis     int      `json:"timeoutMillis"`
	WorkerCount       int      `json:"workerCount"`
	AdaptiveLimit     int      `json:"adaptiveLimit"`
	HTTPPaths         []string `json:"httpPaths,omitempty"`
	DNSQuestion       string   `json:"dnsQuestion,omitempty"`
	EnableUDP         bool     `json:"enableUdp"`
	EnableQUIC        bool     `json:"enableQuic"`
	EnableDNS         bool     `json:"enableDns"`
	EnableWebSocket   bool     `json:"enableWebSocket"`
	AllowInsecureCert bool     `json:"allowInsecureCert"`
}

type ValidatorRequest struct {
	Mode      string                   `json:"mode"`
	Endpoints []ValidatorEndpointInput `json:"endpoints"`
	Options   ValidatorOptions         `json:"options"`
}

type ValidatorRangeOption struct {
	Range     string `json:"range"`
	HostCount int    `json:"hostCount"`
}

type ValidatorRangeImportResult struct {
	Ranges         []ValidatorRangeOption `json:"ranges"`
	Invalid        []string               `json:"invalid"`
	InvalidCount   int                    `json:"invalidCount"`
	DuplicateCount int                    `json:"duplicateCount"`
	TotalCount     int                    `json:"totalCount"`
}

type ValidatorRangeRequest struct {
	Mode    string           `json:"mode"`
	Ranges  []string         `json:"ranges"`
	Port    int              `json:"port"`
	Ports   []int            `json:"ports,omitempty"`
	SNI     string           `json:"sni,omitempty"`
	Options ValidatorOptions `json:"options"`
}

type ScannerStartRequest struct {
	ConnectionProfileID string `json:"connectionProfileId"`
	ScanParallel        int    `json:"scanParallel"`
}

type ScannerState struct {
	Status                      string   `json:"status"`
	Mode                        string   `json:"mode"`
	Paused                      bool     `json:"paused"`
	Phase                       string   `json:"phase"`
	Message                     string   `json:"message"`
	SelectedConnectionProfileID string   `json:"selectedConnectionProfileId"`
	InputFileName               string   `json:"inputFileName"`
	ScanParallel                int      `json:"scanParallel"`
	BootstrapResolverCount      int      `json:"bootstrapResolverCount"`
	RestartAvailable            bool     `json:"restartAvailable"`
	AutoRestart                 bool     `json:"autoRestart"`
	ScannedResolverCount        int      `json:"scannedResolverCount"`
	Total                       int      `json:"total"`
	Completed                   int      `json:"completed"`
	Valid                       int      `json:"valid"`
	Rejected                    int      `json:"rejected"`
	Invalid                     int      `json:"invalid"`
	Duplicates                  int      `json:"duplicates"`
	ValidResolvers              []string `json:"validResolvers"`
	Error                       string   `json:"error"`
	StartedAt                   int64    `json:"startedAt"`
	FinishedAt                  int64    `json:"finishedAt"`
}

type ValidatorState struct {
	Status           string            `json:"status"`
	Paused           bool              `json:"paused"`
	Mode             string            `json:"mode"`
	Total            int               `json:"total"`
	Completed        int               `json:"completed"`
	Retained         int               `json:"retained"`
	Ready            int               `json:"ready"`
	BestScore        int               `json:"bestScore"`
	GradeAPlus       int               `json:"gradeAPlus"`
	GradeA           int               `json:"gradeA"`
	GradeB           int               `json:"gradeB"`
	GradeC           int               `json:"gradeC"`
	GradeF           int               `json:"gradeF"`
	Ports            []int             `json:"ports,omitempty"`
	Results          []ValidatorResult `json:"results"`
	ResultsFileName  string            `json:"resultsFileName,omitempty"`
	ResultsFilePath  string            `json:"resultsFilePath,omitempty"`
	ResultsFileRows  int               `json:"resultsFileRows"`
	ResultsFilePart  int               `json:"resultsFilePart"`
	ResultsFileCount int               `json:"resultsFileCount"`
	RequestedWorkers int               `json:"requestedWorkers"`
	EffectiveWorkers int               `json:"effectiveWorkers"`
	WorkerCeiling    int               `json:"workerCeiling"`
	PressureEvents   int               `json:"pressureEvents"`
	Error            string            `json:"error"`
	StartedAt        int64             `json:"startedAt"`
	FinishedAt       int64             `json:"finishedAt"`
	Options          ValidatorOptions  `json:"options"`
}

type ValidatorResult struct {
	Endpoint       string   `json:"endpoint"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	TCP            bool     `json:"tcp"`
	TLS            bool     `json:"tls"`
	HTTP           bool     `json:"http"`
	WebSocket      bool     `json:"webSocket"`
	UDP            bool     `json:"udp"`
	QUIC           bool     `json:"quic"`
	DNS            bool     `json:"dns"`
	RTTMs          int64    `json:"rttMs"`
	JitterMs       int64    `json:"jitterMs"`
	PacketLoss     float64  `json:"packetLoss"`
	Stability      float64  `json:"stability"`
	Score          int      `json:"score"`
	Grade          string   `json:"grade"`
	Classification string   `json:"classification"`
	Confidence     float64  `json:"confidence"`
	FalsePositive  bool     `json:"falsePositive"`
	Reasons        []string `json:"reasons"`
	Errors         []string `json:"errors,omitempty"`
	RawJSON        string   `json:"rawJson,omitempty"`
}

type ValidatorResultFile struct {
	Name            string `json:"name"`
	RunName         string `json:"runName,omitempty"`
	Part            int    `json:"part"`
	Path            string `json:"path,omitempty"`
	SizeBytes       int64  `json:"sizeBytes"`
	Rows            int    `json:"rows"`
	Status          string `json:"status"`
	Mode            string `json:"mode"`
	Total           int    `json:"total"`
	Completed       int    `json:"completed"`
	Retained        int    `json:"retained"`
	Ready           int    `json:"ready"`
	BestScore       int    `json:"bestScore"`
	StartedAt       int64  `json:"startedAt"`
	FinishedAt      int64  `json:"finishedAt"`
	ModifiedAt      int64  `json:"modifiedAt"`
	ResultsFileName string `json:"resultsFileName,omitempty"`
}

type ParallelTestState struct {
	Status           string                        `json:"status"`
	Phase            string                        `json:"phase"`
	Message          string                        `json:"message"`
	Total            int                           `json:"total"`
	Completed        int                           `json:"completed"`
	Running          int                           `json:"running"`
	ResolverTarget   int                           `json:"resolverTarget"`
	Resolvers        []string                      `json:"resolvers"`
	Candidates       []ParallelTestCandidateResult `json:"candidates"`
	WinnerPresetID   string                        `json:"winnerPresetId"`
	WinnerPresetName string                        `json:"winnerPresetName"`
	Error            string                        `json:"error"`
	StartedAt        int64                         `json:"startedAt"`
	FinishedAt       int64                         `json:"finishedAt"`
}

type ParallelTestCandidateResult struct {
	ID                     string  `json:"id"`
	Name                   string  `json:"name"`
	Status                 string  `json:"status"`
	Stability              float64 `json:"stability"`
	RTTMs                  int64   `json:"rttMs"`
	Score                  int     `json:"score"`
	StartDurationMs        int64   `json:"startDurationMs"`
	DownloadBytesPerSecond int64   `json:"downloadBytesPerSecond"`
	SpeedTestBytes         int64   `json:"speedTestBytes"`
	SpeedTestDurationMs    int64   `json:"speedTestDurationMs"`
	SpeedTestError         string  `json:"speedTestError"`
	Error                  string  `json:"error"`
}

type ParallelTestPresetOption struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Category string          `json:"category"`
	Saved    bool            `json:"saved"`
	Settings SettingsProfile `json:"settings"`
}

func DefaultConnectionProfile() ConnectionProfile {
	return ConnectionProfile{
		ID:               DefaultConnectionProfileID,
		Name:             "Connection",
		ImportType:       ImportTypeMasterDNS,
		EncryptionMethod: 1,
	}
}

func DefaultResolverProfile() ResolverProfile {
	return ResolverProfile{
		ID:   DefaultResolverProfileID,
		Name: "Default Resolver",
		ResolverText: strings.Join([]string{
			"1.1.1.1",
			"1.0.0.1",
			"8.8.8.8",
			"8.8.4.4",
			"9.9.9.9",
			"149.112.112.112",
			"208.67.222.222",
			"208.67.220.220",
			"94.140.14.14",
			"94.140.15.15",
		}, "\n"),
	}
}

func DefaultV2RayProfile() V2RayProfile {
	return V2RayProfile{
		ID:                      DefaultV2RayProfileID,
		Name:                    "V2Ray Connection",
		Protocol:                V2RayProtocolVLESS,
		ServerPort:              443,
		Network:                 "tcp",
		TLS:                     true,
		ShadowsocksMethod:       "2022-blake3-aes-256-gcm",
		UoTVersion:              2,
		HysteriaUDPIdleTimeout:  60,
		WireGuardLocalAddresses: "10.0.0.2/32",
		WireGuardAllowedIPs:     "0.0.0.0/0, ::/0",
		WireGuardMTU:            1420,
		WireGuardNoKernelTun:    true,
		WireGuardDomainStrategy: "ForceIP",
	}
}

func DefaultV2RaySettingsProfile() V2RaySettingsProfile {
	return V2RaySettingsProfile{
		ID:                 DefaultV2RaySettingsID,
		Name:               "Default",
		ListenIP:           "127.0.0.1",
		ListenPort:         10888,
		InboundType:        "mixed",
		SetSystemProxy:     true,
		TunEnabled:         false,
		TunMTU:             1492,
		TunIPv6:            true,
		TunInterfaceName:   DefaultV2RayTunInterfaceName(),
		IranRoutingEnabled: false,
		LogLevel:           "WARN",
	}
}

func DefaultV2RayTunInterfaceName() string {
	switch runtime.GOOS {
	case "windows":
		return "WhiteDNS Tunnel"
	case "darwin":
		return "utun20"
	default:
		return "xray0"
	}
}

func DefaultSettingsProfile() SettingsProfile {
	return SettingsProfile{
		ID:                               DefaultSettingsProfileID,
		Name:                             "Default",
		ImportType:                       ImportTypeMasterDNS,
		ListenIP:                         "127.0.0.1",
		ListenPort:                       10886,
		SOCKSUsername:                    "master_dns_vpn",
		SOCKSPassword:                    "master_dns_vpn",
		SingBoxEnabled:                   true,
		SingBoxInboundType:               "mixed",
		StormDNSListenIP:                 "127.0.0.1",
		StormDNSListenPort:               10887,
		LocalDNSEnabled:                  false,
		LocalDNSPort:                     53,
		BalancingStrategy:                3,
		UploadDuplication:                1,
		DownloadDuplication:              3,
		AutoRemoveLowMTUServers:          true,
		SaveMTUServersToFile:             false,
		MTUServersFileName:               "masterdnsvpn_success_test_{time}.log",
		MTUServersFileFormat:             "{IP} ({DOMAIN}) - UP: {UP_MTU} DOWN: {DOWN-MTU}",
		MTURemovedServerLogFormat:        "Resolver {IP} ({DOMAIN}) removed at {TIME} due to {CAUSE}",
		MTUAddedServerLogFormat:          "Resolver {IP} ({DOMAIN}) added back at {TIME} (UP {UP_MTU}, DOWN {DOWN_MTU})",
		MTUReactiveAddedServerLogFormat:  "Resolver {IP} ({DOMAIN}) added back at {TIME} after reactive recheck (UP {UP_MTU}, DOWN {DOWN_MTU})",
		UploadCompression:                2,
		DownloadCompression:              2,
		MinUploadMTU:                     40,
		MinDownloadMTU:                   300,
		MaxUploadMTU:                     140,
		MaxDownloadMTU:                   3000,
		MTUTestRetriesResolvers:          3,
		MTUTestTimeoutResolvers:          2.5,
		MTUTestParallelismResolvers:      100,
		MTUStartupLossVerifyEnabled:      false,
		MTUStartupLossVerifySamples:      3,
		MTUStartupLossVerifyMaxLossPct:   34,
		MTUStartupLossVerifyCandidates:   3,
		MTURecheckEnabled:                false,
		MTURecheckIntervalMinutes:        5,
		MTUTestRetriesLogs:               5,
		MTUTestTimeoutLogs:               2.5,
		MTUTestParallelismLogs:           32,
		ConnectionStartupMode:            ConnectionStartupModeStandard,
		RXTXWorkers:                      4,
		TunnelProcessWorkers:             4,
		TunnelPacketTimeoutSeconds:       10.0,
		DispatcherIdlePollIntervalSec:    0.020,
		TXChannelSize:                    2048,
		RXChannelSize:                    2048,
		ResolverUDPConnectionPoolSize:    64,
		StreamQueueInitialCapacity:       128,
		OrphanQueueInitialCapacity:       32,
		DNSResponseFragmentStoreCapacity: 256,
		MaxActiveStreams:                 2048,
		LocalHandshakeTimeoutSeconds:     5.0,
		SOCKSUDPAssociateReadTimeoutSec:  30.0,
		ClientTerminalStreamRetentionSec: 45.0,
		ClientCancelledSetupRetentionSec: 120.0,
		SessionInitRetryBaseSeconds:      1.0,
		SessionInitRetryStepSeconds:      1.0,
		SessionInitRetryLinearAfter:      5,
		SessionInitRetryMaxSeconds:       60.0,
		SessionInitBusyRetryIntervalSec:  60.0,
		SessionInitRacingCount:           3,
		StartupMode:                      "resolvers",
		PingWatchdogSeconds:              300,
		LogLevel:                         "WARN",
	}
}

func DefaultAppState() AppState {
	return AppState{
		SelectedConnectionProfileID: DefaultConnectionProfileID,
		SelectedResolverProfileID:   DefaultResolverProfileID,
		SelectedSettingsProfileID:   DefaultSettingsProfileID,
		SelectedV2RayProfileID:      "",
		SelectedV2RaySettingsID:     DefaultV2RaySettingsID,
		SelectedSubscriptionID:      BuiltInSubscriptionID,
		Theme:                       "system",
		ConnectionProfiles:          []ConnectionProfile{DefaultConnectionProfile()},
		ResolverProfiles:            []ResolverProfile{DefaultResolverProfile()},
		SettingsProfiles:            []SettingsProfile{DefaultSettingsProfile()},
		V2RayProfiles:               []V2RayProfile{},
		V2RaySubscriptions:          []V2RaySubscription{},
		V2RaySettingsProfiles:       []V2RaySettingsProfile{DefaultV2RaySettingsProfile()},
		WhiteDNSVPNFrontingIPs:      []string{},
		WhiteVPN:                    DefaultWhiteVPNSettings(),
		Runtime: RuntimeStatus{
			Status: RuntimeDisconnected,
			Logs:   []string{"Idle"},
		},
	}
}

func DefaultParallelTestState() ParallelTestState {
	return ParallelTestState{
		Status:         ParallelTestIdle,
		ResolverTarget: 1,
		Resolvers:      []string{},
		Candidates:     []ParallelTestCandidateResult{},
	}
}

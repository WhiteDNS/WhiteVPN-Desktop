package tunnelengine

type ScanRequest struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	TimeoutMillis     int      `json:"timeoutMillis"`
	Retries           int      `json:"retries"`
	SNI               string   `json:"sni,omitempty"`
	HTTPPaths         []string `json:"httpPaths,omitempty"`
	DNSQuestion       string   `json:"dnsQuestion,omitempty"`
	EnableUDP         bool     `json:"enableUdp"`
	EnableQUIC        bool     `json:"enableQuic"`
	EnableDNS         bool     `json:"enableDns"`
	EnableWebSocket   bool     `json:"enableWebSocket"`
	AllowInsecureCert bool     `json:"allowInsecureCert"`
}

type BatchRequest struct {
	Endpoints         []ScanRequest `json:"endpoints"`
	AdaptiveLimit    int           `json:"adaptiveLimit"`
	TimeoutMillis    int           `json:"timeoutMillis"`
	DefaultRetries   int           `json:"defaultRetries"`
	CancellationHint string        `json:"cancellationHint,omitempty"`
}

type ScanResult struct {
	Endpoint       string         `json:"endpoint"`
	Host           string         `json:"host"`
	Port           int            `json:"port"`
	TCP            TCPResult      `json:"tcp"`
	TLS            TLSResult      `json:"tls"`
	HTTP           HTTPResult     `json:"http"`
	WebSocket      WSResult       `json:"webSocket"`
	UDP            UDPResult      `json:"udp"`
	QUIC           QUICResult     `json:"quic"`
	DNS            DNSResult      `json:"dns"`
	Metrics        Metrics        `json:"metrics"`
	Score          ScoreResult    `json:"score"`
	Errors         []string       `json:"errors,omitempty"`
	ProtocolMatrix map[string]bool `json:"protocolMatrix"`
}

type AttemptMetric struct {
	Success      bool   `json:"success"`
	DurationMs   int64  `json:"durationMs"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

type TCPResult struct {
	Success       bool            `json:"success"`
	Attempts      []AttemptMetric `json:"attempts"`
	MedianRTTMs   int64           `json:"medianRttMs"`
	Consistency   float64         `json:"consistency"`
	ErrorCategory string          `json:"errorCategory,omitempty"`
}

type TLSResult struct {
	Success          bool     `json:"success"`
	HandshakeMs      int64    `json:"handshakeMs"`
	Version          string   `json:"version,omitempty"`
	CipherSuite      string   `json:"cipherSuite,omitempty"`
	ALPN             string   `json:"alpn,omitempty"`
	CertificateCN    string   `json:"certificateCn,omitempty"`
	CertificateSANs  []string `json:"certificateSans,omitempty"`
	Verified         bool     `json:"verified"`
	ErrorCategory    string   `json:"errorCategory,omitempty"`
}

type HTTPProbe struct {
	Method       string `json:"method"`
	URL          string `json:"url"`
	StatusCode   int    `json:"statusCode"`
	DurationMs   int64  `json:"durationMs"`
	Redirected   bool   `json:"redirected"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

type HTTPResult struct {
	Success bool        `json:"success"`
	Probes  []HTTPProbe `json:"probes"`
}

type WSResult struct {
	Success       bool   `json:"success"`
	StatusCode    int    `json:"statusCode"`
	DurationMs    int64  `json:"durationMs"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

type UDPResult struct {
	Reachable     bool            `json:"reachable"`
	Attempts      []AttemptMetric `json:"attempts"`
	ErrorCategory string          `json:"errorCategory,omitempty"`
}

type QUICResult struct {
	Success       bool   `json:"success"`
	HandshakeMs   int64  `json:"handshakeMs"`
	ALPN          string `json:"alpn,omitempty"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

type DNSResult struct {
	UDPResponsive bool            `json:"udpResponsive"`
	TCPResponsive bool            `json:"tcpResponsive"`
	Answers       []string        `json:"answers,omitempty"`
	Attempts      []AttemptMetric `json:"attempts"`
	ErrorCategory string          `json:"errorCategory,omitempty"`
}

type Metrics struct {
	RTTMs              int64   `json:"rttMs"`
	JitterMs           int64   `json:"jitterMs"`
	PacketLossEstimate float64 `json:"packetLossEstimate"`
	StabilityPercent   float64 `json:"stabilityPercent"`
	TimeoutFrequency   float64 `json:"timeoutFrequency"`
}

type ScoreResult struct {
	Numeric        int     `json:"numeric"`
	Grade          string  `json:"grade"`
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	FalsePositive  bool    `json:"falsePositive"`
	Reasons        []string `json:"reasons"`
}

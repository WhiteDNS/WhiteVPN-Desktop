package profiles

import (
	"net/url"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestExportV2RayProfileRoundTripsVLESSLink(t *testing.T) {
	profile := model.V2RayProfile{
		Name:             "vless reality",
		Protocol:         model.V2RayProtocolVLESS,
		Server:           "152.70.58.25",
		ServerPort:       32075,
		UUID:             "11111111-1111-1111-1111-111111111111",
		Flow:             "xtls-rprx-vision",
		PacketEncoding:   "xudp",
		Network:          "tcp",
		TLS:              true,
		SNI:              "www.google.com",
		ALPN:             "h2,http/1.1",
		UTLSFingerprint:  "random",
		Reality:          true,
		RealityPublicKey: "pub",
		RealityShortID:   "sid",
	}

	link, err := ExportV2RayProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("encryption") != "none" {
		t.Fatalf("expected VLESS share link to include encryption=none, got %q", link)
	}
	imported, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 {
		t.Fatalf("expected one imported profile, got %d", len(imported))
	}
	got := imported[0]
	if got.Protocol != profile.Protocol || got.Server != profile.Server || got.ServerPort != profile.ServerPort || got.UUID != profile.UUID {
		t.Fatalf("unexpected exported VLESS identity: %#v", got)
	}
	if !got.Reality || got.Flow != profile.Flow || got.RealityPublicKey != profile.RealityPublicKey || got.RealityShortID != profile.RealityShortID {
		t.Fatalf("expected exported VLESS transport fields, got %#v", got)
	}
	if got.PacketEncoding != profile.PacketEncoding {
		t.Fatalf("expected exported VLESS packet encoding, got %#v", got)
	}
	if got.SNI != profile.SNI || got.ALPN != profile.ALPN || got.UTLSFingerprint != profile.UTLSFingerprint {
		t.Fatalf("expected exported VLESS TLS fields, got %#v", got)
	}
}

func TestExportV2RayProfileRoundTripsTrojanLink(t *testing.T) {
	profile := model.V2RayProfile{
		Name:                     "trojan ws",
		Protocol:                 model.V2RayProtocolTrojan,
		Server:                   "trojan.example.com",
		ServerPort:               443,
		Password:                 "secret",
		Network:                  "ws",
		TLS:                      true,
		SNI:                      "front.example.com",
		ECHConfigList:            "ip.gs+udp://8.8.8.8",
		TransportHost:            "cdn.example.com",
		TransportPath:            "/ws",
		WebSocketEarlyData:       2048,
		WebSocketEarlyDataHeader: "Sec-WebSocket-Protocol",
	}

	link, err := ExportV2RayProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	got := imported[0]
	if got.Protocol != profile.Protocol || got.Password != profile.Password || got.Network != profile.Network || got.TransportPath != profile.TransportPath {
		t.Fatalf("unexpected exported Trojan profile: %#v", got)
	}
	if got.WebSocketEarlyData != profile.WebSocketEarlyData || got.WebSocketEarlyDataHeader != profile.WebSocketEarlyDataHeader {
		t.Fatalf("expected exported Trojan WebSocket early-data fields, got %#v", got)
	}
	if got.ECHConfigList != profile.ECHConfigList {
		t.Fatalf("expected exported Trojan ECH config list, got %#v", got)
	}
}

func TestExportV2RayProfileIncludesWebSocketEarlyDataInShareLink(t *testing.T) {
	profile := model.V2RayProfile{
		Name:                     "vless ws",
		Protocol:                 model.V2RayProtocolVLESS,
		Server:                   "vless.example.com",
		ServerPort:               443,
		UUID:                     "11111111-1111-1111-1111-111111111111",
		Network:                  "ws",
		TLS:                      true,
		SNI:                      "front.example.com",
		TransportHost:            "cdn.example.com",
		TransportPath:            "/ws",
		WebSocketEarlyData:       2048,
		WebSocketEarlyDataHeader: "X-WS-ED",
	}

	link, err := ExportV2RayProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("ed") != "2048" || query.Get("eh") != "X-WS-ED" {
		t.Fatalf("expected exported share link to include WebSocket early-data fields, got %q", link)
	}

	imported, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	got := imported[0]
	if got.WebSocketEarlyData != profile.WebSocketEarlyData || got.WebSocketEarlyDataHeader != profile.WebSocketEarlyDataHeader {
		t.Fatalf("expected WebSocket early-data fields to round-trip, got %#v", got)
	}
}

func TestExportV2RayProfileRoundTripsVMessLink(t *testing.T) {
	profile := model.V2RayProfile{
		Name:            "vmess ws",
		Protocol:        model.V2RayProtocolVMess,
		Server:          "vmess.example.com",
		ServerPort:      443,
		UUID:            "22222222-2222-2222-2222-222222222222",
		AlterID:         0,
		Security:        "auto",
		Network:         "ws",
		TLS:             true,
		SNI:             "vmess.example.com",
		ALPN:            "h2,http/1.1",
		AllowInsecure:   true,
		UTLSFingerprint: "chrome",
		ECHConfigList:   "ip.gs+udp://8.8.8.8",
		TransportHost:   "cdn.example.com",
		TransportPath:   "/vmess",
	}

	link, err := ExportV2RayProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	got := imported[0]
	if got.Protocol != profile.Protocol || got.UUID != profile.UUID || got.Server != profile.Server || got.ServerPort != profile.ServerPort {
		t.Fatalf("unexpected exported VMess identity: %#v", got)
	}
	if !got.TLS || got.Network != profile.Network || got.TransportHost != profile.TransportHost || got.TransportPath != profile.TransportPath {
		t.Fatalf("expected exported VMess transport fields, got %#v", got)
	}
	if got.SNI != profile.SNI || got.ALPN != profile.ALPN || got.UTLSFingerprint != profile.UTLSFingerprint || !got.AllowInsecure {
		t.Fatalf("expected exported VMess TLS fields, got %#v", got)
	}
	if got.ECHConfigList != profile.ECHConfigList {
		t.Fatalf("expected exported VMess ECH config list, got %#v", got)
	}
}

func TestExportV2RayProfileRoundTripsVMessGrpcServiceName(t *testing.T) {
	profile := model.V2RayProfile{
		Name:          "vmess grpc",
		Protocol:      model.V2RayProtocolVMess,
		Server:        "vmess.example.com",
		ServerPort:    443,
		UUID:          "22222222-2222-2222-2222-222222222222",
		Security:      "auto",
		Network:       "grpc",
		TLS:           true,
		SNI:           "vmess.example.com",
		TransportHost: "authority.example.com",
		ServiceName:   "grpc-service",
	}

	link, err := ExportV2RayProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	got := imported[0]
	if got.Network != profile.Network || got.ServiceName != profile.ServiceName || got.TransportPath != "" || got.TransportHost != profile.TransportHost {
		t.Fatalf("expected exported VMess gRPC fields, got %#v", got)
	}
}

func TestExportV2RayProfileUsesVMessH2NetworkName(t *testing.T) {
	profile := model.V2RayProfile{
		Name:          "vmess h2",
		Protocol:      model.V2RayProtocolVMess,
		Server:        "vmess.example.com",
		ServerPort:    443,
		UUID:          "22222222-2222-2222-2222-222222222222",
		Security:      "auto",
		Network:       "http",
		TLS:           true,
		SNI:           "vmess.example.com",
		TransportHost: "cdn.example.com",
		TransportPath: "/h2",
	}

	link, err := ExportV2RayProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decodeV2RayBase64(strings.TrimPrefix(link, model.V2RayProtocolVMess+"://"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"net":"h2"`) {
		t.Fatalf("expected VMess export to use h2 network name, got %s", raw)
	}
}

func TestExportV2RayProfileRoundTripsXHTTPAndHTTPUpgrade(t *testing.T) {
	xhttpProfile := model.V2RayProfile{
		Name:             "vless xhttp",
		Protocol:         model.V2RayProtocolVLESS,
		Server:           "xhttp.example.com",
		ServerPort:       443,
		UUID:             "11111111-1111-1111-1111-111111111111",
		Network:          "xhttp",
		TLS:              true,
		Reality:          true,
		RealityPublicKey: "pub",
		TransportHost:    "front.example.com",
		TransportPath:    "/xhttp",
		XHTTPMode:        "auto",
		XHTTPExtra:       `{"noGRPCHeader":false}`,
	}

	link, err := ExportV2RayProfile(xhttpProfile)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	got := imported[0]
	if got.Network != xhttpProfile.Network || got.TransportHost != xhttpProfile.TransportHost || got.TransportPath != xhttpProfile.TransportPath {
		t.Fatalf("expected XHTTP host/path round-trip, got %#v", got)
	}
	if got.XHTTPMode != xhttpProfile.XHTTPMode || got.XHTTPExtra != xhttpProfile.XHTTPExtra {
		t.Fatalf("expected XHTTP mode/extra round-trip, got %#v", got)
	}

	httpUpgradeProfile := model.V2RayProfile{
		Name:          "trojan httpupgrade",
		Protocol:      model.V2RayProtocolTrojan,
		Server:        "upgrade.example.com",
		ServerPort:    443,
		Password:      "secret",
		Network:       "httpupgrade",
		TLS:           true,
		TransportHost: "cdn.example.com",
		TransportPath: "/upgrade",
	}
	link, err = ExportV2RayProfile(httpUpgradeProfile)
	if err != nil {
		t.Fatal(err)
	}
	imported, err = ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	got = imported[0]
	if got.Network != httpUpgradeProfile.Network || got.TransportHost != httpUpgradeProfile.TransportHost || got.TransportPath != httpUpgradeProfile.TransportPath {
		t.Fatalf("expected HTTPUpgrade round-trip, got %#v", got)
	}
}

func TestExportV2RayProfilesSkipsIncompleteProfiles(t *testing.T) {
	links, err := ExportV2RayProfiles([]model.V2RayProfile{
		model.DefaultV2RayProfile(),
		{
			Name:       "complete",
			Protocol:   model.V2RayProtocolVLESS,
			Server:     "vless.example.com",
			ServerPort: 443,
			UUID:       "11111111-1111-1111-1111-111111111111",
			Network:    "tcp",
			TLS:        true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ParseV2RayProfileImports(links)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 {
		t.Fatalf("expected one exported profile, got %d", len(imported))
	}
	if imported[0].Server != "vless.example.com" {
		t.Fatalf("unexpected imported profile: %#v", imported[0])
	}
}

func TestExportV2RayProfileRoundTripsAdditionalProtocols(t *testing.T) {
	tests := []model.V2RayProfile{
		{
			Name:              "ss",
			Protocol:          model.V2RayProtocolShadowsocks,
			Server:            "ss.example.com",
			ServerPort:        8388,
			ShadowsocksMethod: "aes-256-gcm",
			Password:          "secret",
			UoT:               true,
			UoTVersion:        2,
		},
		{
			Name:                   "hy2",
			Protocol:               model.V2RayProtocolHysteria2,
			Server:                 "hy2.example.com",
			ServerPort:             443,
			HysteriaAuth:           "auth",
			HysteriaUDPIdleTimeout: 90,
			SNI:                    "front.example.com",
			AllowInsecure:          true,
		},
		{
			Name:       "socks",
			Protocol:   model.V2RayProtocolSOCKS,
			Server:     "socks.example.com",
			ServerPort: 1080,
			Username:   "user",
			Password:   "pass",
		},
		{
			Name:        "http",
			Protocol:    model.V2RayProtocolHTTP,
			Server:      "http.example.com",
			ServerPort:  8080,
			Username:    "user",
			Password:    "pass",
			HTTPHeaders: `{"User-Agent":"WhiteDNS"}`,
		},
		{
			Name:                    "wg",
			Protocol:                model.V2RayProtocolWireGuard,
			Server:                  "wg.example.com",
			ServerPort:              51820,
			WireGuardSecretKey:      "private",
			WireGuardLocalAddresses: "10.0.0.2/32",
			WireGuardPeerPublicKey:  "public",
			WireGuardAllowedIPs:     "0.0.0.0/0, ::/0",
			WireGuardNoKernelTun:    true,
		},
	}

	for _, profile := range tests {
		t.Run(profile.Protocol, func(t *testing.T) {
			link, err := ExportV2RayProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			imported, err := ParseV2RayProfileImports(link)
			if err != nil {
				t.Fatal(err)
			}
			if len(imported) != 1 {
				t.Fatalf("expected one imported profile, got %d", len(imported))
			}
			got := imported[0]
			if got.Protocol != profile.Protocol || got.Server != profile.Server || got.ServerPort != profile.ServerPort {
				t.Fatalf("unexpected round-trip profile: %#v", got)
			}
		})
	}
}

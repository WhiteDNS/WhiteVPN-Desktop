package xray

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestRenderConfigCreatesMixedInboundToStormDNS(t *testing.T) {
	settings := model.DefaultSettingsProfile()
	settings.SingBoxInboundType = "mixed"
	settings.SingBoxSetSystemProxy = true
	settings.SOCKS5Authentication = true

	config, err := RenderConfig(settings)
	if err != nil {
		t.Fatal(err)
	}
	root := decodeConfig(t, config)
	inbound := firstObject(t, root, "inbounds")
	if inbound["protocol"] != "mixed" || inbound["tag"] != InboundTag || intValue(inbound["port"]) != 10886 {
		t.Fatalf("unexpected inbound: %#v", inbound)
	}
	inboundSettings := inbound["settings"].(map[string]any)
	if inboundSettings["auth"] != "password" {
		t.Fatalf("expected password auth: %#v", inboundSettings)
	}
	outbound := firstObject(t, root, "outbounds")
	outboundSettings := outbound["settings"].(map[string]any)
	if outbound["protocol"] != "socks" || outbound["tag"] != OutboundTag || intValue(outboundSettings["port"]) != 10887 {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
	if strings.Contains(config, "set_system_proxy") || strings.Contains(config, "listen_port") {
		t.Fatalf("config should use Xray schema, got:\n%s", config)
	}
}

func TestMasterDNSSettingsUsesInternalPort(t *testing.T) {
	settings := model.DefaultSettingsProfile()
	masterSettings := MasterDNSSettings(settings)
	if masterSettings.ListenPort != settings.StormDNSListenPort {
		t.Fatalf("expected MasterDNS port %d, got %d", settings.StormDNSListenPort, masterSettings.ListenPort)
	}
}

func TestRenderV2RayConfigCreatesDirectVLESSOutbound(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Name = "VLESS"
	profile.Server = "example.com"
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "ws"
	profile.TransportPath = "/ws"
	profile.TransportHost = "cdn.example.com"
	profile.WebSocketEarlyData = 2048
	profile.PacketEncoding = "xudp"
	profile.SNI = "front.example.com"
	profile.Reality = true
	profile.RealityPublicKey = "pub"
	profile.RealityShortID = "abc"
	profile.UTLSFingerprint = "chrome"
	settings := model.DefaultV2RaySettingsProfile()

	config, err := RenderV2RayConfig(profile, settings)
	if err != nil {
		t.Fatal(err)
	}
	root := decodeConfig(t, config)
	inbounds := root["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("expected only the local inbound when TUN is disabled, got %#v", inbounds)
	}
	inbound := inbounds[0].(map[string]any)
	if inbound["protocol"] != "mixed" || intValue(inbound["port"]) != settings.ListenPort {
		t.Fatalf("unexpected inbound: %#v", inbound)
	}
	outbound := firstObject(t, root, "outbounds")
	if outbound["protocol"] != "vless" || outbound["tag"] != V2RayOutboundTag {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
	outboundSettings := outbound["settings"].(map[string]any)
	if outboundSettings["address"] != "example.com" || outboundSettings["id"] != profile.UUID || outboundSettings["packetEncoding"] != "xudp" {
		t.Fatalf("unexpected VLESS settings: %#v", outboundSettings)
	}
	stream := outbound["streamSettings"].(map[string]any)
	if stream["network"] != "websocket" || stream["security"] != "reality" {
		t.Fatalf("unexpected stream settings: %#v", stream)
	}
	ws := stream["wsSettings"].(map[string]any)
	if ws["host"] != "cdn.example.com" || !strings.Contains(ws["path"].(string), "ed=2048") {
		t.Fatalf("unexpected WebSocket settings: %#v", ws)
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["serverName"] != "front.example.com" || reality["password"] != "pub" || reality["shortId"] != "abc" {
		t.Fatalf("unexpected Reality settings: %#v", reality)
	}
}

func TestRenderV2RayConfigSupportsXrayTransports(t *testing.T) {
	settings := model.DefaultV2RaySettingsProfile()
	tests := []struct {
		name       string
		network    string
		configure  func(*model.V2RayProfile)
		wantStream string
		wantKey    string
	}{
		{name: "mKCP", network: "kcp", wantStream: "mkcp", wantKey: "kcpSettings"},
		{
			name:    "gRPC",
			network: "grpc",
			configure: func(profile *model.V2RayProfile) {
				profile.ServiceName = "service"
				profile.TransportHost = "grpc.example.com"
			},
			wantStream: "grpc",
			wantKey:    "grpcSettings",
		},
		{
			name:    "HTTPUpgrade",
			network: "httpupgrade",
			configure: func(profile *model.V2RayProfile) {
				profile.TransportHost = "cdn.example.com"
				profile.TransportPath = "/upgrade"
			},
			wantStream: "httpupgrade",
			wantKey:    "httpupgradeSettings",
		},
		{
			name:    "XHTTP",
			network: "xhttp",
			configure: func(profile *model.V2RayProfile) {
				profile.TransportHost = "cdn.example.com"
				profile.TransportPath = "/xhttp"
				profile.XHTTPMode = "auto"
			},
			wantStream: "xhttp",
			wantKey:    "xhttpSettings",
		},
		{name: "HTTP2Legacy", network: "http", wantStream: "xhttp", wantKey: "xhttpSettings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := model.DefaultV2RayProfile()
			profile.Name = tt.name
			profile.Server = "example.com"
			profile.UUID = "11111111-1111-1111-1111-111111111111"
			profile.Network = tt.network
			if tt.configure != nil {
				tt.configure(&profile)
			}

			config, err := RenderV2RayConfig(profile, settings)
			if err != nil {
				t.Fatal(err)
			}
			stream := firstObject(t, decodeConfig(t, config), "outbounds")["streamSettings"].(map[string]any)
			if stream["network"] != tt.wantStream {
				t.Fatalf("expected network %q, got %#v", tt.wantStream, stream)
			}
			if _, ok := stream[tt.wantKey]; !ok {
				t.Fatalf("expected %s in stream settings: %#v", tt.wantKey, stream)
			}
		})
	}
}

func TestRenderV2RayConfigUsesTransportHostAsServerNameWhenDialingIP(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Server = "69.84.182.49"
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "xhttp"
	profile.TLS = true
	profile.TransportHost = "v.whitedns.best"
	profile.TransportPath = "/2015"
	profile.XHTTPMode = "auto"
	profile.ECHConfigList = "ip.gs+udp://8.8.8.8"

	config, err := RenderV2RayConfig(profile, model.DefaultV2RaySettingsProfile())
	if err != nil {
		t.Fatal(err)
	}
	stream := firstObject(t, decodeConfig(t, config), "outbounds")["streamSettings"].(map[string]any)
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "v.whitedns.best" {
		t.Fatalf("expected transport host as TLS serverName, got %#v", tlsSettings)
	}
	if tlsSettings["echConfigList"] != profile.ECHConfigList {
		t.Fatalf("expected ECH config list in TLS settings, got %#v", tlsSettings)
	}
	if got := V2RayTransportServerName(profile); got != "v.whitedns.best" {
		t.Fatalf("expected effective server name from transport host, got %q", got)
	}
}

func TestRenderV2RayConfigRejectsQUIC(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Server = "example.com"
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	profile.Network = "quic"

	_, err := RenderV2RayConfig(profile, model.DefaultV2RaySettingsProfile())
	if err == nil || !strings.Contains(err.Error(), "QUIC transport is not supported") {
		t.Fatalf("expected QUIC support error, got %v", err)
	}
}

func TestRenderV2RayConfigAllowsLANInbound(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Server = "example.com"
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	settings := model.DefaultV2RaySettingsProfile()
	settings.AllowLAN = true

	config, err := RenderV2RayConfig(profile, settings)
	if err != nil {
		t.Fatal(err)
	}
	inbound := firstObject(t, decodeConfig(t, config), "inbounds")
	if inbound["listen"] != "0.0.0.0" {
		t.Fatalf("expected LAN inbound to listen on all interfaces: %#v", inbound)
	}
}

func TestRenderV2RayConfigAddsTunInbound(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Server = "example.com"
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	settings := model.DefaultV2RaySettingsProfile()
	settings.TunEnabled = true
	settings.TunMTU = 1400
	settings.TunInterfaceName = "xray-test0"

	config, err := RenderV2RayConfig(profile, settings)
	if err != nil {
		t.Fatal(err)
	}
	root := decodeConfig(t, config)
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("expected local and TUN inbounds, got %#v", root["inbounds"])
	}
	localInbound, ok := inbounds[0].(map[string]any)
	if !ok || localInbound["tag"] != InboundTag || localInbound["protocol"] != "mixed" {
		t.Fatalf("expected local mixed inbound to remain first, got %#v", inbounds[0])
	}
	tunInbound, ok := inbounds[1].(map[string]any)
	if !ok || tunInbound["tag"] != TunInboundTag || tunInbound["protocol"] != "tun" || intValue(tunInbound["port"]) != 0 {
		t.Fatalf("unexpected TUN inbound: %#v", inbounds[1])
	}
	tunSettings := tunInbound["settings"].(map[string]any)
	if tunSettings["name"] != "xray-test0" || intValue(tunSettings["MTU"]) != 1400 {
		t.Fatalf("unexpected TUN settings: %#v", tunSettings)
	}
	routing := root["routing"].(map[string]any)
	rules, ok := routing["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected one TUN routing rule, got %#v", routing["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["outboundTag"] != V2RayOutboundTag {
		t.Fatalf("expected TUN route to V2Ray outbound, got %#v", rule)
	}
	inboundTags, ok := rule["inboundTag"].([]any)
	if !ok || len(inboundTags) != 1 || inboundTags[0] != TunInboundTag {
		t.Fatalf("expected TUN inboundTag routing rule, got %#v", rule)
	}
}

func TestRenderV2RayConfigAddsIranRoutingGeodata(t *testing.T) {
	profile := model.DefaultV2RayProfile()
	profile.Server = "example.com"
	profile.UUID = "11111111-1111-1111-1111-111111111111"
	settings := model.DefaultV2RaySettingsProfile()
	settings.IranRoutingEnabled = true

	config, err := RenderV2RayConfig(profile, settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(config, ".srs") || strings.Contains(config, "geosite-malware") {
		t.Fatalf("Xray routing should not reference sing-box SRS rule sets:\n%s", config)
	}
	required := []string{"geoip:private", "geoip:ir", "geosite:category-ir", "geosite:category-ads-all", `"protocol": "blackhole"`}
	for _, fragment := range required {
		if !strings.Contains(config, fragment) {
			t.Fatalf("routing config missing %q:\n%s", fragment, config)
		}
	}
}

func TestRenderV2RayConfigSupportsAdditionalXrayOutbounds(t *testing.T) {
	settings := model.DefaultV2RaySettingsProfile()
	tests := []struct {
		name     string
		profile  model.V2RayProfile
		protocol string
		assert   func(t *testing.T, outbound map[string]any)
	}{
		{
			name: "Shadowsocks",
			profile: model.V2RayProfile{
				Name:              "ss",
				Protocol:          model.V2RayProtocolShadowsocks,
				Server:            "ss.example.com",
				ServerPort:        8388,
				ShadowsocksMethod: "2022-blake3-aes-256-gcm",
				Password:          "secret",
				UoT:               true,
				UoTVersion:        2,
			},
			protocol: "shadowsocks",
			assert: func(t *testing.T, outbound map[string]any) {
				settings := outbound["settings"].(map[string]any)
				if settings["method"] != "2022-blake3-aes-256-gcm" || settings["password"] != "secret" || settings["uot"] != true {
					t.Fatalf("unexpected Shadowsocks settings: %#v", settings)
				}
			},
		},
		{
			name: "Hysteria2",
			profile: model.V2RayProfile{
				Name:                   "hy2",
				Protocol:               model.V2RayProtocolHysteria2,
				Server:                 "hy2.example.com",
				ServerPort:             443,
				HysteriaAuth:           "auth",
				HysteriaUDPIdleTimeout: 90,
				HysteriaMasquerade:     `{"type":"string","content":"ok"}`,
			},
			protocol: "hysteria",
			assert: func(t *testing.T, outbound map[string]any) {
				stream := outbound["streamSettings"].(map[string]any)
				hysteria := stream["hysteriaSettings"].(map[string]any)
				if stream["network"] != "hysteria" || intValue(hysteria["version"]) != 2 || hysteria["auth"] != "auth" {
					t.Fatalf("unexpected Hysteria stream settings: %#v", stream)
				}
			},
		},
		{
			name: "WireGuard",
			profile: model.V2RayProfile{
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
			protocol: "wireguard",
			assert: func(t *testing.T, outbound map[string]any) {
				settings := outbound["settings"].(map[string]any)
				if _, ok := outbound["streamSettings"]; ok {
					t.Fatalf("WireGuard should not render streamSettings: %#v", outbound)
				}
				if settings["secretKey"] != "private" || settings["noKernelTun"] != true {
					t.Fatalf("unexpected WireGuard settings: %#v", settings)
				}
			},
		},
		{
			name: "SOCKS",
			profile: model.V2RayProfile{
				Name:       "socks",
				Protocol:   model.V2RayProtocolSOCKS,
				Server:     "socks.example.com",
				ServerPort: 1080,
				Username:   "user",
				Password:   "pass",
			},
			protocol: "socks",
			assert: func(t *testing.T, outbound map[string]any) {
				settings := outbound["settings"].(map[string]any)
				if settings["user"] != "user" || settings["pass"] != "pass" {
					t.Fatalf("unexpected SOCKS settings: %#v", settings)
				}
			},
		},
		{
			name: "HTTP",
			profile: model.V2RayProfile{
				Name:        "http",
				Protocol:    model.V2RayProtocolHTTP,
				Server:      "http.example.com",
				ServerPort:  8080,
				Username:    "user",
				Password:    "pass",
				TLS:         true,
				HTTPHeaders: `{"User-Agent":"WhiteDNS"}`,
			},
			protocol: "http",
			assert: func(t *testing.T, outbound map[string]any) {
				settings := outbound["settings"].(map[string]any)
				if settings["user"] != "user" || settings["headers"].(map[string]any)["User-Agent"] != "WhiteDNS" {
					t.Fatalf("unexpected HTTP settings: %#v", settings)
				}
				if outbound["streamSettings"].(map[string]any)["security"] != "tls" {
					t.Fatalf("expected HTTP TLS stream settings: %#v", outbound)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := RenderV2RayConfig(tt.profile, settings)
			if err != nil {
				t.Fatal(err)
			}
			outbound := firstObject(t, decodeConfig(t, config), "outbounds")
			if outbound["protocol"] != tt.protocol {
				t.Fatalf("expected protocol %q, got %#v", tt.protocol, outbound)
			}
			tt.assert(t, outbound)
		})
	}
}

func TestRenderedConfigsValidateWithXrayBinary(t *testing.T) {
	xrayBin := strings.TrimSpace(os.Getenv("WHITEDNS_XRAY_TEST_BIN"))
	if xrayBin == "" {
		t.Skip("WHITEDNS_XRAY_TEST_BIN is not set")
	}
	masterSettings := model.DefaultSettingsProfile()
	masterConfig, err := RenderConfig(masterSettings)
	if err != nil {
		t.Fatal(err)
	}
	v2rayProfile := model.DefaultV2RayProfile()
	v2rayProfile.Server = "example.com"
	v2rayProfile.UUID = "11111111-1111-1111-1111-111111111111"
	v2rayProfile.Network = "ws"
	v2rayProfile.TransportPath = "/ws"
	v2rayProfile.TLS = true
	v2rayConfig, err := RenderV2RayConfig(v2rayProfile, model.DefaultV2RaySettingsProfile())
	if err != nil {
		t.Fatal(err)
	}
	v2rayXHTTPProfile := model.DefaultV2RayProfile()
	v2rayXHTTPProfile.Server = "69.84.182.49"
	v2rayXHTTPProfile.UUID = "11111111-1111-1111-1111-111111111111"
	v2rayXHTTPProfile.Network = "xhttp"
	v2rayXHTTPProfile.TLS = true
	v2rayXHTTPProfile.TransportHost = "v.whitedns.best"
	v2rayXHTTPProfile.TransportPath = "/2015"
	v2rayXHTTPProfile.XHTTPMode = "auto"
	v2rayXHTTPConfig, err := RenderV2RayConfig(v2rayXHTTPProfile, model.DefaultV2RaySettingsProfile())
	if err != nil {
		t.Fatal(err)
	}
	iranSettings := model.DefaultV2RaySettingsProfile()
	iranSettings.IranRoutingEnabled = true
	v2rayIranConfig, err := RenderV2RayConfig(v2rayProfile, iranSettings)
	if err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]string{
		"masterdns":      masterConfig,
		"v2ray":          v2rayConfig,
		"v2ray-xhttp-ip": v2rayXHTTPConfig,
		"v2ray-iran":     v2rayIranConfig,
	} {
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), name+".json")
			if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(xrayBin, "run", "-test", "-c", configPath)
			cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(xrayBin))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("xray validation failed: %v\n%s\nconfig:\n%s", err, output, config)
			}
		})
	}
}

func decodeConfig(t *testing.T, raw string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	return root
}

func firstObject(t *testing.T, root map[string]any, key string) map[string]any {
	t.Helper()
	items, ok := root[key].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("missing %s: %#v", key, root)
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected %s[0]: %#v", key, items[0])
	}
	return item
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return 0
	}
}

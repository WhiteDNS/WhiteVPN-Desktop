package profiles

import (
	"encoding/base64"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestParseV2RayProfileImportsParsesVLESSAndTrojanLinks(t *testing.T) {
	raw := `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=ws&serverName=front.example.com&path=%2Fws&host=cdn.example.com&utls=chrome&pbk=pub&sid=abc&ed=2048&eh=X-WS-ED&allow_insecure=1#VLESS%20One
trojan://secret@example.net:8443?type=grpc&serviceName=tunnel#Trojan`

	profiles, err := ParseV2RayProfileImports(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}

	vless := profiles[0]
	if vless.Protocol != model.V2RayProtocolVLESS || vless.Name != "VLESS One" || vless.UUID == "" {
		t.Fatalf("unexpected VLESS profile: %#v", vless)
	}
	if !vless.TLS || !vless.Reality || vless.Network != "ws" || vless.TransportPath != "/ws" || vless.TransportHost != "cdn.example.com" {
		t.Fatalf("expected VLESS TLS/reality/ws fields, got %#v", vless)
	}
	if vless.SNI != "front.example.com" || vless.UTLSFingerprint != "chrome" || !vless.AllowInsecure {
		t.Fatalf("expected VLESS TLS aliases to import, got %#v", vless)
	}
	if vless.WebSocketEarlyData != 2048 || vless.WebSocketEarlyDataHeader != "X-WS-ED" {
		t.Fatalf("expected VLESS WebSocket early-data fields, got %#v", vless)
	}

	trojan := profiles[1]
	if trojan.Protocol != model.V2RayProtocolTrojan || trojan.Password != "secret" || !trojan.TLS || trojan.Network != "grpc" || trojan.ServiceName != "tunnel" {
		t.Fatalf("unexpected Trojan profile: %#v", trojan)
	}
}

func TestParseV2RayProfileImportsParsesECHConfigList(t *testing.T) {
	raw := `vless://cc752a3e-1537-4e86-bb50-1b897bf7b33c@202.37.33.80:443?encryption=none&security=tls&sni=cyylr.eu.cc&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&ech=ip.gs%2Budp%3A%2F%2F8.8.8.8&type=ws&host=cyylr.eu.cc&path=%2Fsg-melbi#ECH`

	profiles, err := ParseV2RayProfileImports(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one profile, got %d", len(profiles))
	}
	profile := profiles[0]
	if profile.ECHConfigList != "ip.gs+udp://8.8.8.8" {
		t.Fatalf("expected ECH config list to import, got %#v", profile)
	}
}

func TestParseV2RayProfileImportsParsesVMessShareJSON(t *testing.T) {
	payload := `{"ps":"VMess One","add":"vmess.example.com","port":"443","id":"22222222-2222-2222-2222-222222222222","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/vmess","tls":"tls","sni":"vmess.example.com","alpn":"h2,http/1.1","fp":"chrome","ech":"ip.gs+udp://8.8.8.8","allowInsecure":"1"}`
	link := "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(payload))

	profiles, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one profile, got %d", len(profiles))
	}
	profile := profiles[0]
	if profile.Protocol != model.V2RayProtocolVMess || profile.Name != "VMess One" || profile.Server != "vmess.example.com" || profile.ServerPort != 443 {
		t.Fatalf("unexpected VMess profile: %#v", profile)
	}
	if !profile.TLS || profile.Network != "ws" || profile.TransportHost != "cdn.example.com" || profile.TransportPath != "/vmess" {
		t.Fatalf("expected VMess TLS/ws fields, got %#v", profile)
	}
	if profile.ALPN != "h2,http/1.1" || profile.UTLSFingerprint != "chrome" || !profile.AllowInsecure {
		t.Fatalf("expected VMess TLS options, got %#v", profile)
	}
	if profile.ECHConfigList != "ip.gs+udp://8.8.8.8" {
		t.Fatalf("expected VMess ECH config list, got %#v", profile)
	}
}

func TestParseV2RayProfileImportsParsesVMessGrpcServiceName(t *testing.T) {
	payload := `{"ps":"VMess gRPC","add":"vmess.example.com","port":443,"id":"22222222-2222-2222-2222-222222222222","aid":0,"scy":"auto","net":"grpc","host":"authority.example.com","path":"grpc-service","tls":"tls","sni":"vmess.example.com"}`
	link := "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(payload))

	profiles, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatal(err)
	}
	profile := profiles[0]
	if profile.Network != "grpc" || profile.ServiceName != "grpc-service" || profile.TransportPath != "" || profile.TransportHost != "authority.example.com" {
		t.Fatalf("expected VMess gRPC fields, got %#v", profile)
	}
}

func TestParseV2RayProfileImportsParsesHTTPUpgradeXHTTPAndQUIC(t *testing.T) {
	raw := `vless://11111111-1111-1111-1111-111111111111@upgrade.example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fupgrade#HTTPUpgrade
vless://22222222-2222-2222-2222-222222222222@xhttp.example.com:443?security=reality&type=xhttp&host=front.example.com&path=%2Fxhttp&mode=auto&extra=%7B%22noGRPCHeader%22%3Afalse%7D&pbk=pub#XHTTP
trojan://secret@quic.example.com:443?type=quic#QUIC`

	profiles, err := ParseV2RayProfileImports(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}

	httpUpgrade := profiles[0]
	if httpUpgrade.Network != "httpupgrade" || httpUpgrade.TransportHost != "cdn.example.com" || httpUpgrade.TransportPath != "/upgrade" {
		t.Fatalf("expected HTTPUpgrade fields, got %#v", httpUpgrade)
	}

	xhttp := profiles[1]
	if xhttp.Network != "xhttp" || xhttp.TransportHost != "front.example.com" || xhttp.TransportPath != "/xhttp" {
		t.Fatalf("expected XHTTP host/path fields, got %#v", xhttp)
	}
	if xhttp.XHTTPMode != "auto" || xhttp.XHTTPExtra != `{"noGRPCHeader":false}` || !xhttp.Reality {
		t.Fatalf("expected XHTTP mode/extra/reality fields, got %#v", xhttp)
	}

	if profiles[2].Network != "quic" {
		t.Fatalf("expected QUIC network, got %#v", profiles[2])
	}
}

func TestParseV2RayProfileImportsSkipsInvalidLinksAndCanonicalizesEscapedQueries(t *testing.T) {
	raw := `vless://@bad.example.com:443?type=ws#MissingUUID
vless://33333333-3333-3333-3333-333333333333@example.com:443?path=%2F&amp%3Bsecurity=tls&amp%3Btype=kcp&amp%3BpacketEncoding=xudp&amp%3Bsni=front.example.com#Escaped`

	profiles, err := ParseV2RayProfileImports(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected invalid profile to be skipped, got %d profiles", len(profiles))
	}
	profile := profiles[0]
	if profile.Network != "kcp" || !profile.TLS || profile.PacketEncoding != "xudp" || profile.SNI != "front.example.com" {
		t.Fatalf("expected escaped query parameters to import, got %#v", profile)
	}
}

func TestParseV2RayProfileImportsParsesAdditionalProtocolLinks(t *testing.T) {
	raw := `ss://YWVzLTI1Ni1nY206c2VjcmV0QHNzLmV4YW1wbGUuY29tOjgzODg#SS
hy2://auth@hy2.example.com:443?sni=front.example.com&insecure=1#HY2
socks5://user:pass@socks.example.com:1080#SOCKS
http-proxy://user:pass@http.example.com:8080?headers=%7B%22User-Agent%22%3A%22WhiteDNS%22%7D#HTTP`

	profiles, err := ParseV2RayProfileImports(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 4 {
		t.Fatalf("expected 4 profiles, got %d", len(profiles))
	}
	if profiles[0].Protocol != model.V2RayProtocolShadowsocks || profiles[0].ShadowsocksMethod != "aes-256-gcm" || profiles[0].Password != "secret" {
		t.Fatalf("unexpected Shadowsocks profile: %#v", profiles[0])
	}
	if profiles[1].Protocol != model.V2RayProtocolHysteria2 || profiles[1].HysteriaAuth != "auth" || !profiles[1].AllowInsecure {
		t.Fatalf("unexpected Hysteria2 profile: %#v", profiles[1])
	}
	if profiles[2].Protocol != model.V2RayProtocolSOCKS || profiles[2].Username != "user" || profiles[2].Password != "pass" {
		t.Fatalf("unexpected SOCKS profile: %#v", profiles[2])
	}
	if profiles[3].Protocol != model.V2RayProtocolHTTP || profiles[3].HTTPHeaders != `{"User-Agent":"WhiteDNS"}` {
		t.Fatalf("unexpected HTTP profile: %#v", profiles[3])
	}
}

func TestParseV2RayProfileImportsParsesWireGuardConfig(t *testing.T) {
	raw := `[Interface]
PrivateKey = private
Address = 10.0.0.2/32
MTU = 1420

[Peer]
PublicKey = public
PresharedKey = shared
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = wg.example.com:51820
PersistentKeepalive = 25`

	profiles, err := ParseV2RayProfileImports(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one WireGuard profile, got %d", len(profiles))
	}
	profile := profiles[0]
	if profile.Protocol != model.V2RayProtocolWireGuard || profile.WireGuardSecretKey != "private" || profile.WireGuardPeerPublicKey != "public" || profile.Server != "wg.example.com" {
		t.Fatalf("unexpected WireGuard profile: %#v", profile)
	}
	if !profile.WireGuardNoKernelTun {
		t.Fatalf("expected WireGuard noKernelTun default, got %#v", profile)
	}
}

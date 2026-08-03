package profiles

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/model"
)

type vmessExportShare struct {
	V              string `json:"v"`
	PS             string `json:"ps"`
	Add            string `json:"add"`
	Port           string `json:"port"`
	ID             string `json:"id"`
	AID            string `json:"aid"`
	Scy            string `json:"scy"`
	Net            string `json:"net"`
	Type           string `json:"type"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	TLS            string `json:"tls"`
	SNI            string `json:"sni"`
	ALPN           string `json:"alpn,omitempty"`
	FP             string `json:"fp,omitempty"`
	ECH            string `json:"ech,omitempty"`
	AllowInsecure  bool   `json:"allowInsecure,omitempty"`
	PacketEncoding string `json:"packetEncoding,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Extra          string `json:"extra,omitempty"`
}

func ExportV2RayProfile(profile model.V2RayProfile) (string, error) {
	profile = NormalizeV2RayProfile(profile)
	if err := validateV2RayProfileForExport(profile); err != nil {
		return "", err
	}

	switch profile.Protocol {
	case model.V2RayProtocolVMess:
		return exportVMessProfile(profile)
	case model.V2RayProtocolTrojan:
		return exportV2RayURLProfile(profile, profile.Password, nil), nil
	case model.V2RayProtocolShadowsocks:
		return exportShadowsocksProfile(profile), nil
	case model.V2RayProtocolHysteria2:
		return exportHysteriaProfile(profile), nil
	case model.V2RayProtocolWireGuard:
		return exportWireGuardProfile(profile), nil
	case model.V2RayProtocolSOCKS:
		return exportUserPassProxyProfile(profile, "socks5"), nil
	case model.V2RayProtocolHTTP:
		scheme := "http-proxy"
		if profile.TLS {
			scheme = "https-proxy"
		}
		return exportUserPassProxyProfile(profile, scheme), nil
	default:
		return exportV2RayURLProfile(profile, profile.UUID, func(q url.Values) {
			if profile.Flow != "" {
				q.Set("flow", profile.Flow)
			}
		}), nil
	}
}

func ExportV2RayProfiles(items []model.V2RayProfile) (string, error) {
	links := make([]string, 0, len(items))
	for _, item := range items {
		if !IsExportableV2RayProfile(item) {
			continue
		}
		link, err := ExportV2RayProfile(item)
		if err != nil {
			return "", err
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return "", fmt.Errorf("no complete V2Ray profiles to export")
	}
	return strings.Join(links, "\n"), nil
}

func IsExportableV2RayProfile(profile model.V2RayProfile) bool {
	profile = NormalizeV2RayProfile(profile)
	if strings.TrimSpace(profile.Server) == "" {
		return false
	}
	switch profile.Protocol {
	case model.V2RayProtocolTrojan, model.V2RayProtocolShadowsocks:
		return strings.TrimSpace(profile.Password) != ""
	case model.V2RayProtocolHysteria2:
		return strings.TrimSpace(profile.HysteriaAuth) != ""
	case model.V2RayProtocolWireGuard:
		return strings.TrimSpace(profile.WireGuardSecretKey) != "" && strings.TrimSpace(profile.WireGuardPeerPublicKey) != ""
	case model.V2RayProtocolSOCKS, model.V2RayProtocolHTTP:
		return true
	default:
		return strings.TrimSpace(profile.UUID) != ""
	}
}

func validateV2RayProfileForExport(profile model.V2RayProfile) error {
	if strings.TrimSpace(profile.Server) == "" {
		return fmt.Errorf("V2Ray server is required")
	}
	if profile.ServerPort <= 0 || profile.ServerPort > 65535 {
		return fmt.Errorf("valid V2Ray server port is required")
	}
	switch profile.Protocol {
	case model.V2RayProtocolTrojan:
		if strings.TrimSpace(profile.Password) == "" {
			return fmt.Errorf("Trojan password is required")
		}
	case model.V2RayProtocolShadowsocks:
		if strings.TrimSpace(profile.ShadowsocksMethod) == "" {
			return fmt.Errorf("Shadowsocks method is required")
		}
		if strings.TrimSpace(profile.Password) == "" {
			return fmt.Errorf("Shadowsocks password is required")
		}
	case model.V2RayProtocolHysteria2:
		if strings.TrimSpace(profile.HysteriaAuth) == "" {
			return fmt.Errorf("Hysteria2 auth is required")
		}
	case model.V2RayProtocolWireGuard:
		if strings.TrimSpace(profile.WireGuardSecretKey) == "" {
			return fmt.Errorf("WireGuard secret key is required")
		}
		if strings.TrimSpace(profile.WireGuardPeerPublicKey) == "" {
			return fmt.Errorf("WireGuard peer public key is required")
		}
	case model.V2RayProtocolSOCKS, model.V2RayProtocolHTTP:
		return nil
	default:
		if strings.TrimSpace(profile.UUID) == "" {
			return fmt.Errorf("%s UUID is required", v2rayProtocolExportLabel(profile.Protocol))
		}
	}
	return nil
}

func exportShadowsocksProfile(profile model.V2RayProfile) string {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte(profile.ShadowsocksMethod + ":" + profile.Password))
	q := url.Values{}
	if profile.UoT {
		q.Set("uot", "1")
		q.Set("uotVersion", strconv.Itoa(profile.UoTVersion))
	}
	u := url.URL{
		Scheme:   "ss",
		User:     url.User(userInfo),
		Host:     net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort)),
		RawQuery: q.Encode(),
		Fragment: profile.Name,
	}
	return u.String()
}

func exportHysteriaProfile(profile model.V2RayProfile) string {
	q := url.Values{}
	if profile.SNI != "" {
		q.Set("sni", profile.SNI)
	}
	if profile.ALPN != "" {
		q.Set("alpn", profile.ALPN)
	}
	if profile.AllowInsecure {
		q.Set("insecure", "1")
	}
	if profile.HysteriaUDPIdleTimeout > 0 {
		q.Set("udpIdleTimeout", strconv.Itoa(profile.HysteriaUDPIdleTimeout))
	}
	if profile.HysteriaMasquerade != "" {
		q.Set("masquerade", profile.HysteriaMasquerade)
	}
	u := url.URL{
		Scheme:   "hy2",
		User:     url.User(profile.HysteriaAuth),
		Host:     net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort)),
		RawQuery: q.Encode(),
		Fragment: profile.Name,
	}
	return u.String()
}

func exportUserPassProxyProfile(profile model.V2RayProfile, scheme string) string {
	q := url.Values{"proxy": []string{"1"}}
	if profile.Protocol == model.V2RayProtocolHTTP {
		if profile.SNI != "" {
			q.Set("sni", profile.SNI)
		}
		if profile.AllowInsecure {
			q.Set("insecure", "1")
		}
		if profile.HTTPHeaders != "" {
			q.Set("headers", profile.HTTPHeaders)
		}
	}
	u := url.URL{
		Scheme:   scheme,
		Host:     net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort)),
		RawQuery: q.Encode(),
		Fragment: profile.Name,
	}
	if profile.Username != "" || profile.Password != "" {
		u.User = url.UserPassword(profile.Username, profile.Password)
	}
	return u.String()
}

func exportWireGuardProfile(profile model.V2RayProfile) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + profile.WireGuardSecretKey + "\n")
	if profile.WireGuardLocalAddresses != "" {
		b.WriteString("Address = " + profile.WireGuardLocalAddresses + "\n")
	}
	if profile.WireGuardMTU > 0 {
		b.WriteString("MTU = " + strconv.Itoa(profile.WireGuardMTU) + "\n")
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + profile.WireGuardPeerPublicKey + "\n")
	if profile.WireGuardPreSharedKey != "" {
		b.WriteString("PresharedKey = " + profile.WireGuardPreSharedKey + "\n")
	}
	if profile.WireGuardAllowedIPs != "" {
		b.WriteString("AllowedIPs = " + profile.WireGuardAllowedIPs + "\n")
	}
	b.WriteString("Endpoint = " + net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort)) + "\n")
	if profile.WireGuardKeepAlive > 0 {
		b.WriteString("PersistentKeepalive = " + strconv.Itoa(profile.WireGuardKeepAlive) + "\n")
	}
	return strings.TrimSpace(b.String())
}

func exportV2RayURLProfile(profile model.V2RayProfile, username string, apply func(url.Values)) string {
	q := v2rayURLShareQuery(profile)
	if apply != nil {
		apply(q)
	}
	u := url.URL{
		Scheme:   profile.Protocol,
		User:     url.User(username),
		Host:     net.JoinHostPort(profile.Server, strconv.Itoa(profile.ServerPort)),
		RawQuery: q.Encode(),
		Fragment: profile.Name,
	}
	return u.String()
}

func v2rayURLShareQuery(profile model.V2RayProfile) url.Values {
	q := url.Values{}
	switch {
	case profile.Reality:
		q.Set("security", "reality")
	case profile.TLS:
		q.Set("security", "tls")
	default:
		q.Set("security", "none")
	}
	if profile.Network != "" {
		q.Set("type", profile.Network)
	}
	if profile.SNI != "" {
		q.Set("sni", profile.SNI)
	}
	if profile.ALPN != "" {
		q.Set("alpn", profile.ALPN)
	}
	if profile.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	if profile.UTLSFingerprint != "" {
		q.Set("fp", profile.UTLSFingerprint)
	}
	if profile.ECHConfigList != "" {
		q.Set("ech", profile.ECHConfigList)
	}
	if profile.RealityPublicKey != "" {
		q.Set("pbk", profile.RealityPublicKey)
	}
	if profile.RealityShortID != "" {
		q.Set("sid", profile.RealityShortID)
	}
	if profile.Protocol == model.V2RayProtocolVLESS {
		q.Set("encryption", "none")
	}
	if profile.PacketEncoding != "" {
		q.Set("packetEncoding", profile.PacketEncoding)
	}
	if profile.TransportPath != "" {
		q.Set("path", profile.TransportPath)
	}
	if profile.TransportHost != "" {
		q.Set("host", profile.TransportHost)
	}
	if profile.ServiceName != "" {
		q.Set("serviceName", profile.ServiceName)
	}
	if profile.XHTTPMode != "" {
		q.Set("mode", profile.XHTTPMode)
	}
	if profile.XHTTPExtra != "" {
		q.Set("extra", profile.XHTTPExtra)
	}
	if profile.WebSocketEarlyData > 0 {
		q.Set("ed", strconv.Itoa(profile.WebSocketEarlyData))
		if profile.WebSocketEarlyDataHeader != "" && profile.WebSocketEarlyDataHeader != "Sec-WebSocket-Protocol" {
			q.Set("eh", profile.WebSocketEarlyDataHeader)
		}
	}
	return q
}

func exportVMessProfile(profile model.V2RayProfile) (string, error) {
	payload := vmessExportShare{
		V:              "2",
		PS:             profile.Name,
		Add:            profile.Server,
		Port:           strconv.Itoa(profile.ServerPort),
		ID:             profile.UUID,
		AID:            strconv.Itoa(profile.AlterID),
		Scy:            profile.Security,
		Net:            vmessShareNetwork(profile.Network),
		Type:           "none",
		Host:           profile.TransportHost,
		Path:           vmessSharePath(profile),
		SNI:            profile.SNI,
		ALPN:           profile.ALPN,
		FP:             profile.UTLSFingerprint,
		ECH:            profile.ECHConfigList,
		AllowInsecure:  profile.AllowInsecure,
		PacketEncoding: profile.PacketEncoding,
		Mode:           profile.XHTTPMode,
		Extra:          profile.XHTTPExtra,
	}
	if profile.TLS {
		payload.TLS = "tls"
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return model.V2RayProtocolVMess + "://" + base64.RawStdEncoding.EncodeToString(raw), nil
}

func vmessShareNetwork(network string) string {
	if network == "http" {
		return "h2"
	}
	return network
}

func vmessSharePath(profile model.V2RayProfile) string {
	if profile.Network == "grpc" {
		return profile.ServiceName
	}
	return profile.TransportPath
}

func v2rayProtocolExportLabel(protocol string) string {
	switch protocol {
	case model.V2RayProtocolVMess:
		return "VMess"
	case model.V2RayProtocolShadowsocks:
		return "Shadowsocks"
	case model.V2RayProtocolHysteria2:
		return "Hysteria2"
	case model.V2RayProtocolWireGuard:
		return "WireGuard"
	case model.V2RayProtocolSOCKS:
		return "SOCKS"
	case model.V2RayProtocolHTTP:
		return "HTTP"
	default:
		return "VLESS"
	}
}

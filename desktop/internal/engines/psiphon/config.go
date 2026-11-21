// Package psiphon runs the pinned psiphon-tunnel-core ConsoleClient as the
// desktop's Psiphon engine. config.go is Android's PsiphonConfigBuilder
// (engines/models/PsiphonProfile.kt); keep the two in step.
package psiphon

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/engineprofiles"
)

const (
	ModeAuto   = "auto"
	ModeCDN    = "cdn"
	ModeDirect = "direct"

	propagationChannelID   = "FFFFFFFFFFFFFFFF"
	sponsorID              = "FFFFFFFFFFFFFFFF"
	serverListURL          = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	serverListSignatureKey = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH" +
		"5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5" +
		"OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot" +
		"LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6" +
		"/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G" +
		"stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O" +
		"geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8" +
		"u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz" +
		"31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal" +
		"KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
)

var (
	cdnProtocols = []string{"FRONTED-MEEK-CDN-OSSH", "FRONTED-MEEK-CDN-HTTP-OSSH", "FRONTED-MEEK-CDN-QUIC-OSSH"}

	nonInproxyProtocols = []string{
		"SSH", "OSSH", "TLS-OSSH",
		"UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH", "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
		"QUIC-OSSH", "SHADOWSOCKS-OSSH",
		"FRONTED-MEEK-OSSH", "FRONTED-MEEK-CDN-OSSH", "FRONTED-MEEK-HTTP-OSSH",
		"FRONTED-MEEK-CDN-HTTP-OSSH", "FRONTED-MEEK-QUIC-OSSH", "FRONTED-MEEK-CDN-QUIC-OSSH",
	}
)

func mode(raw string) string {
	switch strings.TrimSpace(raw) {
	case ModeCDN:
		return ModeCDN
	case ModeDirect:
		return ModeDirect
	}
	return ModeAuto
}

// BuildConfig renders the tunnel-core JSON config for one session.
func BuildConfig(p engineprofiles.PsiphonConfig, dataDir string, socksPort, httpPort int) ([]byte, error) {
	c := map[string]any{
		"PropagationChannelId":                      propagationChannelID,
		"SponsorId":                                 sponsorID,
		"ClientVersion":                             "1",
		"DataRootDirectory":                         dataDir,
		"LocalSocksProxyPort":                       socksPort,
		"LocalHttpProxyPort":                        httpPort,
		"EmitDiagnosticNotices":                     true,
		"EmitDiagnosticNetworkParameters":           true,
		"RemoteServerListURLs":                      []any{map[string]any{"URL": base64.StdEncoding.EncodeToString([]byte(serverListURL))}},
		"RemoteServerListSignaturePublicKey":        serverListSignatureKey,
		"InproxyTunnelProtocolPreferProbability":    0.0,
		"InproxyTunnelProtocolSelectionProbability": 0.0,
	}
	if region := strings.ToUpper(strings.TrimSpace(p.Country)); region != "" {
		c["EgressRegion"] = region
	}
	putCDNFronting(c, p)
	switch mode(p.Mode) {
	case ModeCDN:
		c["LimitTunnelProtocols"] = cdnProtocols
		c["DisableTactics"] = true
	case ModeDirect:
		direct := []string{}
		for _, protocol := range nonInproxyProtocols {
			if !strings.HasPrefix(protocol, "FRONTED-") {
				direct = append(direct, protocol)
			}
		}
		c["LimitTunnelProtocols"] = direct
		c["DisableTactics"] = true
	default:
		c["LimitTunnelProtocols"] = nonInproxyProtocols
	}
	return json.Marshal(c)
}

func putCDNFronting(c map[string]any, p engineprofiles.PsiphonConfig) {
	addresses := IPCandidates(strings.Join(p.CDNIPs, " "))
	serverNames := SNICandidates(p.CDNSNI)
	if len(addresses) == 0 {
		c["FrontedMeekCDNScanUseBuiltInSpec"] = true
	} else {
		spec := map[string]any{"IPCandidates": addresses}
		if len(serverNames) > 0 {
			spec["SNIServerNames"] = serverNames
		}
		c["FrontedMeekCDNScanSpec"] = spec
	}
	dial := addresses
	if len(dial) == 0 {
		dial = serverNames
	}
	if len(dial) == 0 || len(serverNames) == 0 {
		return
	}
	c["FrontedMeekDialOverrides"] = []any{map[string]any{
		"OverrideID":              "user",
		"MatchDialAddressRegexes": []string{".*"},
		"DialAddresses":           dial,
		"SNIServerName":           serverNames[0],
		"VerifyServerNames":       serverNames,
	}}
}

func split(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return strings.ContainsRune(" \t\n\r,;", r) })
}

// IPCandidates keeps IPv4 addresses and IPv4 CIDRs, as Android does.
func IPCandidates(raw string) []string {
	out := []string{}
	for _, v := range split(raw) {
		if (isIPv4(v) || isIPv4CIDR(v)) && !contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func SNICandidates(raw string) []string {
	out := []string{}
	for _, v := range split(raw) {
		if h := normalizeHostname(v); h != "" && !contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// Android checks dotted-quad text, so leading zeros like 01.2.3.4 still count.
func isIPv4(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if p == "" || len(p) > 3 || err != nil || n > 255 || strings.ContainsAny(p, "+-") {
			return false
		}
	}
	return true
}

func isIPv4CIDR(v string) bool {
	ip, bits, ok := strings.Cut(v, "/")
	n, err := strconv.Atoi(bits)
	return ok && isIPv4(ip) && bits != "" && err == nil && n <= 32 && !strings.ContainsAny(bits, "+-")
}

func normalizeHostname(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	v, _, _ = strings.Cut(v, "/")
	v = strings.Trim(v, ".")
	if v == "" || !strings.Contains(v, ".") {
		return ""
	}
	for _, r := range v {
		if r > 127 || !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return ""
		}
	}
	return v
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

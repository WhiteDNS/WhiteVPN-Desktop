package profiles

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/model"
)

const DefaultWhiteIPList = `# WhiteDNS IP lists
# Format: host:port
[cloudflare]
69.84.182.49:443
104.17.121.71:443
45.130.125.76:443
172.67.200.192:443
104.19.85.243:443
190.93.244.89:443
188.114.106.89:443
104.18.153.88:443
104.24.249.191:443
141.101.82.1:443
104.19.198.153:443
198.41.199.54:443
162.159.143.224:443
198.41.223.167:443
141.101.115.170:443
198.41.192.107:443
103.22.200.57:443
104.25.130.62:443
108.162.244.68:443
103.31.4.90:443
103.21.247.70:443
141.101.67.58:443
103.31.4.240:443
103.22.200.134:443
103.21.246.97:443
104.27.124.169:443
104.18.145.146:443
173.245.59.111:443
173.245.49.238:443
162.158.184.6:443
172.68.184.129:443
103.21.246.77:443
162.159.60.176:443
188.114.102.196:443
190.93.246.62:443
103.31.4.230:443
108.162.227.79:443
103.22.203.45:443
108.162.241.97:443
198.41.215.122:443
172.65.170.28:443
162.158.185.62:443
104.18.0.149:443
104.27.24.189:443
162.159.17.54:443
103.31.4.251:443
198.41.202.17:443
197.234.242.154:443
198.41.222.238:443
104.16.34.40:443
197.234.243.77:443
198.41.214.7:443
172.71.99.115:443
104.21.83.56:443
104.21.74.192:443
103.31.4.172:443
108.162.244.107:443
141.101.69.69:443
104.21.54.105:443
104.17.52.123:443
104.27.37.226:443
108.162.247.40:443
103.31.4.241:443
104.24.162.220:443
141.101.104.216:443
103.21.246.219:443
172.67.158.89:443
198.41.201.63:443
103.22.201.117:443
141.101.68.90:443
162.158.199.97:443
103.22.201.49:443
190.93.247.80:443
104.17.165.247:443
103.21.246.48:443
104.27.113.60:443
197.234.241.72:443
162.158.96.183:443
141.101.76.99:443
104.16.103.75:443
197.234.240.13:443
103.21.246.114:443
173.245.49.172:443
103.21.246.64:443
104.19.104.109:443
197.234.241.158:443
103.31.4.70:443
172.71.217.132:443
162.159.126.137:443
108.162.198.146:443
108.162.217.232:443
190.93.244.231:443
103.21.246.209:443
162.159.231.51:443
103.21.246.200:443
197.234.243.151:443`

type WhiteIPEndpoint struct {
	Host string
	Port int
}

func (endpoint WhiteIPEndpoint) String() string {
	return net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
}

func ParseWhiteIPEndpoints(rawText string) ([]WhiteIPEndpoint, error) {
	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(rawText, "\r\n", "\n"), "\r", "\n"), "\n")
	seen := map[string]struct{}{}
	endpoints := make([]WhiteIPEndpoint, 0, len(lines))
	for idx, rawLine := range lines {
		line := strings.TrimSpace(strings.TrimPrefix(rawLine, "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || isWhiteIPSection(line) {
			continue
		}
		endpoint, err := parseWhiteIPEndpoint(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", idx+1, err)
		}
		key := strings.ToLower(endpoint.String())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no valid White IP endpoints found")
	}
	return endpoints, nil
}

func ConvertV2RayProfilesToWhiteIPs(configText string, whiteIPText string) ([]model.V2RayProfile, int, int, error) {
	sourceProfiles, err := ParseV2RayProfileImports(configText)
	if err != nil {
		return nil, 0, 0, err
	}
	endpoints, err := ParseWhiteIPEndpoints(whiteIPText)
	if err != nil {
		return nil, len(sourceProfiles), 0, err
	}
	converted := make([]model.V2RayProfile, 0, len(sourceProfiles)*len(endpoints))
	for _, source := range sourceProfiles {
		source = NormalizeV2RayProfile(source)
		originalHost := strings.TrimSpace(source.Server)
		for _, endpoint := range endpoints {
			profile := source
			profile.ID = ""
			profile.SubscriptionID = ""
			profile.Name = whiteIPProfileName(source.Name, endpoint)
			if originalHostIsDomain(originalHost) {
				if strings.TrimSpace(profile.SNI) == "" {
					profile.SNI = originalHost
				}
				if strings.TrimSpace(profile.TransportHost) == "" {
					profile.TransportHost = originalHost
				}
			}
			profile.Server = endpoint.Host
			profile.ServerPort = endpoint.Port
			converted = append(converted, NormalizeV2RayProfile(profile))
		}
	}
	return converted, len(sourceProfiles), len(endpoints), nil
}

func isWhiteIPSection(line string) bool {
	return strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")
}

func parseWhiteIPEndpoint(line string) (WhiteIPEndpoint, error) {
	host, portText, err := splitWhiteIPHostPort(line)
	if err != nil {
		return WhiteIPEndpoint{}, err
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return WhiteIPEndpoint{}, fmt.Errorf("host is required")
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < 1 || port > 65535 {
		return WhiteIPEndpoint{}, fmt.Errorf("port must be between 1 and 65535")
	}
	return WhiteIPEndpoint{Host: host, Port: port}, nil
}

func splitWhiteIPHostPort(line string) (string, string, error) {
	if host, port, err := net.SplitHostPort(line); err == nil {
		return host, port, nil
	}
	lastColon := strings.LastIndex(line, ":")
	if lastColon < 1 || lastColon == len(line)-1 {
		return "", "", fmt.Errorf("expected host:port")
	}
	host := strings.TrimSpace(line[:lastColon])
	port := strings.TrimSpace(line[lastColon+1:])
	if strings.Contains(host, ":") && !(strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")) {
		return "", "", fmt.Errorf("IPv6 endpoints must use [host]:port")
	}
	return host, port, nil
}

func whiteIPProfileName(sourceName string, endpoint WhiteIPEndpoint) string {
	name := strings.TrimSpace(sourceName)
	if name == "" {
		name = "V2Ray Connection"
	}
	return fmt.Sprintf("%s - %s", name, endpoint.String())
}

func originalHostIsDomain(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	return host != "" && net.ParseIP(host) == nil
}

// Package fragment defines the FinalMask settings shared by persistence and
// configuration generation. The presets match WhiteVPN Android 1.7.1.
package fragment

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Settings struct {
	Enabled      bool   `json:"enabled"`
	RawJSON      string `json:"rawJson"`
	ALPN         string `json:"alpn"`
	CipherSuites string `json:"cipherSuites"`
}

const DefaultCipherSuites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:" +
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" +
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:" +
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

func Presets() []string {
	values := [][4]string{{"13-23", "1-5", "7-17", "1-4"}, {"10-15", "1-2", "6-12", "1"},
		{"10-20", "1-6", "6-14", "2-4"}, {"15-30", "1-2", "10-20", "1-2"},
		{"8-14", "1-3", "5-10", "0-1"}, {"12-20", "1-3", "2-6", "2-4"}}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprintf(`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["%s"],"delays":["0"],"maxSplit":"256"}},{"type":"fragment","settings":{"packets":"%s","lengths":["%s"],"delays":["%s"],"maxSplit":"256"}}]}`, v[0], v[1], v[2], v[3]))
	}
	return out
}

func Default() Settings {
	return Settings{RawJSON: Presets()[0], ALPN: "http/1.1", CipherSuites: DefaultCipherSuites}
}

// Validate also formats JSON and migrates Android 1.7.0's legacy maxSplit=0.
// Blank ALPN/ciphers intentionally retain the server's own settings.
func Validate(s Settings) (Settings, error) {
	stages, err := Parse(s.RawJSON)
	if err != nil {
		return s, err
	}
	tcp := make([]map[string]any, 0, len(stages))
	for _, stage := range stages {
		tcp = append(tcp, map[string]any{"type": "fragment", "settings": stage})
	}
	formatted, _ := json.MarshalIndent(map[string]any{"tcp": tcp}, "", "  ")
	s.RawJSON = string(formatted)
	alpn := []string{}
	for _, value := range strings.Split(s.ALPN, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > 255 || strings.ContainsAny(value, " \t\r\n\x00") {
			return s, fmt.Errorf("ALPN must contain comma-separated protocol names")
		}
		alpn = append(alpn, value)
	}
	s.ALPN = strings.Join(alpn, ",")
	supported := map[string]bool{}
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		supported[suite.Name] = true
	}
	ciphers := []string{}
	if strings.TrimSpace(s.CipherSuites) != "" {
		for _, value := range strings.Split(s.CipherSuites, ":") {
			value = strings.TrimSpace(value)
			if !supported[value] {
				return s, fmt.Errorf("unsupported TLS cipher suite")
			}
			ciphers = append(ciphers, value)
		}
	}
	s.CipherSuites = strings.Join(ciphers, ":")
	return s, nil
}

func Parse(raw string) ([]map[string]any, error) {
	if len(raw) > 65536 {
		return nil, fmt.Errorf("fragment JSON exceeds 64 KiB")
	}
	var root struct {
		TCP []struct {
			Type     string                     `json:"type"`
			Settings map[string]json.RawMessage `json:"settings"`
		} `json:"tcp"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid fragment JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid fragment JSON: trailing content")
	}
	if len(root.TCP) < 1 || len(root.TCP) > 8 {
		return nil, fmt.Errorf("tcp must contain 1–8 fragment stages")
	}
	out := make([]map[string]any, 0, len(root.TCP))
	for i, item := range root.TCP {
		if item.Type != "fragment" || item.Settings == nil {
			return nil, fmt.Errorf("tcp[%d] must have type fragment and settings", i)
		}
		stage := map[string]any{}
		for key, rawValue := range item.Settings {
			switch key {
			case "packets":
				var value string
				if json.Unmarshal(rawValue, &value) != nil {
					return nil, fmt.Errorf("packets must be tlshello or a positive range")
				}
				value = strings.TrimSpace(value)
				if value != "" && value != "tlshello" {
					if _, min, _, err := parseRange(rawValue); err != nil || min < 1 {
						return nil, fmt.Errorf("packets must be tlshello or a positive range")
					}
				}
				stage[key] = value
			case "length", "lengths", "delay", "delays", "interval", "maxSplit", "max-split":
				var values []json.RawMessage
				list := strings.HasSuffix(key, "s")
				if list {
					if json.Unmarshal(rawValue, &values) != nil || len(values) < 1 || len(values) > 256 {
						return nil, fmt.Errorf("%s must contain 1–256 ranges", key)
					}
				} else {
					values = []json.RawMessage{rawValue}
				}
				normalized := []string{}
				for n, v := range values {
					value, min, max, err := parseRange(v)
					if err != nil {
						return nil, fmt.Errorf("invalid %s range", key)
					}
					switch key {
					case "length", "lengths":
						if n == len(values)-1 && min == 0 {
							return nil, fmt.Errorf("the final length must start above zero")
						}
					case "maxSplit", "max-split":
						if min == 0 && max == 0 {
							value = "256"
						} else if min < 1 || max > 256 {
							return nil, fmt.Errorf("maxSplit must be between 1 and 256")
						}
					default:
						if max > 1000 {
							return nil, fmt.Errorf("fragment delay must not exceed 1000 ms")
						}
					}
					normalized = append(normalized, value)
				}
				if list {
					stage[key] = normalized
				} else {
					stage[key] = normalized[0]
				}
			default:
				return nil, fmt.Errorf("unsupported fragment setting")
			}
		}
		if countKeys(stage, "length", "lengths") != 1 {
			return nil, fmt.Errorf("use exactly one of length or lengths")
		}
		if countKeys(stage, "delay", "delays", "interval") > 1 {
			return nil, fmt.Errorf("use only one of delay, delays, or interval")
		}
		if countKeys(stage, "maxSplit", "max-split") > 1 {
			return nil, fmt.Errorf("use only one of maxSplit or max-split")
		}
		out = append(out, stage)
	}
	return out, nil
}

func countKeys(m map[string]any, keys ...string) int {
	n := 0
	for _, key := range keys {
		if _, ok := m[key]; ok {
			n++
		}
	}
	return n
}

func parseRange(raw json.RawMessage) (string, int64, int64, error) {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		value = string(raw)
	}
	value = strings.TrimSpace(value)
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return "", 0, 0, fmt.Errorf("invalid range")
	}
	numbers := make([]int64, 0, len(parts))
	for _, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return "", 0, 0, fmt.Errorf("invalid range")
		}
		n, err := strconv.ParseInt(part, 10, 32)
		if err != nil {
			return "", 0, 0, err
		}
		numbers = append(numbers, n)
	}
	min, max := numbers[0], numbers[len(numbers)-1]
	if min > max {
		min, max = max, min
	}
	normalized := strconv.FormatInt(min, 10)
	if min != max {
		normalized += "-" + strconv.FormatInt(max, 10)
	}
	return normalized, min, max, nil
}

type Variant struct {
	Name     string
	Settings Settings
}

func StartupVariants(s Settings) []Variant {
	if !s.Enabled {
		return []Variant{{"normal", s}}
	}
	out := []Variant{{"full", s}}
	plain := s
	plain.ALPN, plain.CipherSuites = "", ""
	if plain != s {
		out = append(out, Variant{"fragments-only", plain})
	}
	plain = s
	plain.Enabled = false
	return append(out, Variant{"normal", plain})
}

package profiles

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"whitevpn-desktop/internal/model"
)

const stormDNSProfileSchema = "whitedns.profile"

var stormDNSProfileURLPattern = regexp.MustCompile(`(?i)(stormdns|masterdns)://([A-Za-z0-9+/_=-]+)`)

type stormDNSProfilePayload struct {
	Schema     string `json:"schema"`
	Version    int    `json:"version"`
	ImportType string `json:"import_type,omitempty"`
	Profile    struct {
		Name   string                `json:"name"`
		Server stormDNSProfileServer `json:"server"`
	} `json:"profile"`
}

type stormDNSProfileServer struct {
	Domain                string `json:"domain"`
	EncryptionKey         string `json:"encryption_key"`
	EncryptionKeyCamel    string `json:"encryptionKey,omitempty"`
	EncryptionMethod      *int   `json:"encryption_method"`
	EncryptionMethodCamel *int   `json:"encryptionMethod,omitempty"`
}

func ParseConnectionProfileImports(rawText, resolverProfileID string, importType string) ([]model.ConnectionProfile, error) {
	matches := stormDNSProfileURLPattern.FindAllStringSubmatch(rawText, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no MasterDNS/StormDNS profiles found")
	}

	profiles := make([]model.ConnectionProfile, 0, len(matches))
	for idx, match := range matches {
		profile, err := parseStormDNSProfile(match[2], resolverProfileID, importTypeFromScheme(match[1], importType))
		if err != nil {
			return nil, fmt.Errorf("profile %d: %w", idx+1, err)
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func ExportConnectionProfile(profile model.ConnectionProfile) (string, error) {
	name := strings.TrimSpace(profile.Name)
	domain := strings.TrimSpace(strings.TrimSuffix(profile.Domain, "."))
	key := strings.TrimSpace(profile.EncryptionKey)
	if domain == "" {
		return "", fmt.Errorf("MasterDNS/StormDNS domain is required")
	}
	if key == "" {
		return "", fmt.Errorf("MasterDNS/StormDNS encryption key is required")
	}
	method := profile.EncryptionMethod
	if method < 0 || method > 5 {
		return "", fmt.Errorf("unsupported encryption method")
	}
	if name == "" {
		name = domain
	}

	payload := stormDNSProfilePayload{
		Schema:     stormDNSProfileSchema,
		Version:    1,
		ImportType: model.NormalizeImportType(profile.ImportType),
	}
	payload.Profile.Name = name
	payload.Profile.Server.Domain = domain
	payload.Profile.Server.EncryptionKey = key
	payload.Profile.Server.EncryptionMethod = &method

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return model.NormalizeImportType(profile.ImportType) + "://" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func ExportConnectionProfiles(connectionProfiles []model.ConnectionProfile) (string, error) {
	links := make([]string, 0, len(connectionProfiles))
	for _, profile := range connectionProfiles {
		if !IsExportableConnectionProfile(profile) {
			continue
		}
		link, err := ExportConnectionProfile(profile)
		if err != nil {
			return "", err
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return "", fmt.Errorf("no complete connection profiles to export")
	}
	return strings.Join(links, "\n"), nil
}

func IsExportableConnectionProfile(profile model.ConnectionProfile) bool {
	return strings.TrimSpace(strings.TrimSuffix(profile.Domain, ".")) != "" && strings.TrimSpace(profile.EncryptionKey) != ""
}

func parseStormDNSProfile(encoded, resolverProfileID string, importType string) (model.ConnectionProfile, error) {
	raw, err := decodeStormDNSProfile(encoded)
	if err != nil {
		return model.ConnectionProfile{}, err
	}

	var payload stormDNSProfilePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return model.ConnectionProfile{}, fmt.Errorf("invalid profile JSON")
	}
	if payload.Schema != stormDNSProfileSchema {
		return model.ConnectionProfile{}, fmt.Errorf("unsupported profile schema")
	}
	if payload.Version != 1 {
		return model.ConnectionProfile{}, fmt.Errorf("unsupported profile version")
	}
	if strings.TrimSpace(importType) == "" {
		importType = payload.ImportType
	}
	if strings.TrimSpace(importType) == "" {
		importType = model.ImportTypeMasterDNS
	}

	domain := strings.TrimSpace(strings.TrimSuffix(payload.Profile.Server.Domain, "."))
	if domain == "" {
		return model.ConnectionProfile{}, fmt.Errorf("MasterDNS/StormDNS domain is required")
	}

	key := strings.TrimSpace(payload.Profile.Server.EncryptionKey)
	if key == "" {
		key = strings.TrimSpace(payload.Profile.Server.EncryptionKeyCamel)
	}
	if key == "" {
		return model.ConnectionProfile{}, fmt.Errorf("MasterDNS/StormDNS encryption key is required")
	}

	method := 1
	if payload.Profile.Server.EncryptionMethod != nil {
		method = *payload.Profile.Server.EncryptionMethod
	} else if payload.Profile.Server.EncryptionMethodCamel != nil {
		method = *payload.Profile.Server.EncryptionMethodCamel
	}
	if method < 0 || method > 5 {
		return model.ConnectionProfile{}, fmt.Errorf("unsupported encryption method")
	}

	name := strings.TrimSpace(payload.Profile.Name)
	if name == "" {
		name = domain
	}

	return model.ConnectionProfile{
		Name:              name,
		ImportType:        model.NormalizeImportType(importType),
		Domain:            domain,
		EncryptionKey:     key,
		EncryptionMethod:  method,
		ResolverProfileID: strings.TrimSpace(resolverProfileID),
	}, nil
}

func importTypeFromScheme(scheme string, requested string) string {
	if strings.TrimSpace(requested) != "" {
		return model.NormalizeImportType(requested)
	}
	if model.NormalizeImportType(scheme) == model.ImportTypeStormDNS {
		return ""
	}
	return model.NormalizeImportType(scheme)
}

func decodeStormDNSProfile(encoded string) ([]byte, error) {
	value := strings.TrimSpace(encoded)
	if value == "" {
		return nil, fmt.Errorf("empty profile payload")
	}

	padded := value
	if remainder := len(padded) % 4; remainder != 0 {
		padded += strings.Repeat("=", 4-remainder)
	}

	attempts := []struct {
		encoding *base64.Encoding
		value    string
	}{
		{base64.StdEncoding, padded},
		{base64.URLEncoding, padded},
		{base64.RawStdEncoding, strings.TrimRight(value, "=")},
		{base64.RawURLEncoding, strings.TrimRight(value, "=")},
	}
	for _, attempt := range attempts {
		raw, err := attempt.encoding.DecodeString(attempt.value)
		if err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 profile payload")
}

package psiphon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Android's PsiphonRegions: public, non-secret metadata. The seed is
// RegionListPreference.java, Psiphon-Inc/psiphon-android revision
// c2c043da1208b34d28c3fdeef72b43dcd470dacb; the core updates availability.
var KnownCodes = []string{"AE", "AR", "AT", "AU", "BE", "BG", "BR", "CA", "CH", "CL", "CO", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HK", "HU", "HR", "ID", "IE", "IN", "IS", "IT", "JP", "KE", "KR", "LT", "LV", "MX", "MY", "NL", "NO", "NZ", "PL", "PT", "RO", "RS", "SE", "SG", "SK", "TW", "UA", "US", "ZA"}

const regionsFile = "psiphon-egress-regions.json"

func Normalize(regions []string) []string {
	if len(regions) > 256 {
		regions = regions[:256]
	}
	out := []string{}
	for _, r := range regions {
		code := strings.ToUpper(strings.TrimSpace(r))
		if len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' && !contains(out, code) {
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}

// Record keeps the regions the core last reported, replacing the file whole.
func Record(dir string, regions []string) error {
	codes := Normalize(regions)
	if len(codes) == 0 {
		return nil
	}
	raw, _ := json.Marshal(codes)
	tmp := filepath.Join(dir, regionsFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, regionsFile))
}

// Options is the country picker: "" (automatic) first, then the recorded
// regions, or the seed before the core has reported any, plus the stored
// selection so it is never silently dropped. The UI sorts by display name.
func Options(dir, selected string) []string {
	available := KnownCodes
	if raw, err := os.ReadFile(filepath.Join(dir, regionsFile)); err == nil && len(raw) <= 4096 {
		var codes []string
		if json.Unmarshal(raw, &codes) == nil && len(codes) <= 256 {
			if codes = Normalize(codes); len(codes) > 0 {
				available = codes
			}
		}
	}
	return append([]string{""}, Normalize(append(append([]string{}, available...), selected))...)
}

package fragment

import (
	"strings"
	"testing"
)

func TestAndroid171PresetsAndLegacyMigration(t *testing.T) {
	for i, raw := range Presets() {
		s := Default()
		s.RawJSON = raw
		valid, err := Validate(s)
		if err != nil {
			t.Fatalf("preset %d: %v", i+1, err)
		}
		stages, _ := Parse(valid.RawJSON)
		if len(stages) != 2 || stages[0]["packets"] != "tlshello" || stages[0]["maxSplit"] != "256" {
			t.Fatalf("preset %d: %v", i+1, stages)
		}
		again, err := Validate(valid)
		if err != nil || again != valid {
			t.Fatal("formatting is not stable")
		}
	}
	s := Settings{RawJSON: `{"tcp":[{"type":"fragment","settings":{"lengths":[0,104,1],"maxSplit":"0"}}]}`}
	valid, err := Validate(s)
	if err != nil || !strings.Contains(valid.RawJSON, `"maxSplit": "256"`) {
		t.Fatalf("legacy migration: %v, %s", err, valid.RawJSON)
	}
	if valid.ALPN != "" || valid.CipherSuites != "" {
		t.Fatal("blank TLS overrides must stay blank")
	}
}

func TestRejectInvalidSettingsBeforeTheyReachTheCore(t *testing.T) {
	for _, fields := range []string{
		`"lengths":["1"],"maxSplit":"257"`, `"lengths":["1"],"maxSplit":"0-1"`,
		`"lengths":["0"]`, `"lengths":[]`, `"lengths":["1"],"length":"2"`,
		`"lengths":["1"],"delays":["1001"]`, `"lengths":["1"],"delay":"1","interval":"2"`,
		`"lengths":["1"],"maxSplit":"1","max-split":"2"`, `"lengths":["1"],"packets":"0-1"`,
		`"lengths":["2147483648"]`, `"lengths":["-1"]`, `"lengths":[1.1]`, `"lengths":["1"],"unknown":true`,
	} {
		t.Run(fields, func(t *testing.T) {
			_, err := Parse(`{"tcp":[{"type":"fragment","settings":{` + fields + `}}]}`)
			if err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
	for _, raw := range []string{`{}`, `{"tcp":[]}`, `{"tcp":[{"type":"fragment"}]}`, Presets()[0] + ` {}`, strings.Repeat(" ", 65537)} {
		if _, err := Parse(raw); err == nil {
			t.Fatal("invalid document accepted")
		}
	}
	for _, change := range []func(*Settings){func(s *Settings) { s.ALPN = "h2\r\nbad" }, func(s *Settings) { s.CipherSuites = "not-a-cipher" }} {
		s := Default()
		change(&s)
		if _, err := Validate(s); err == nil {
			t.Fatal("invalid TLS override accepted")
		}
	}
}

func TestStartupVariantsKeepRequestedSettings(t *testing.T) {
	s := Default()
	s.Enabled = true
	v := StartupVariants(s)
	if len(v) != 3 || v[0].Name != "full" || v[1].Name != "fragments-only" || v[2].Name != "normal" {
		t.Fatalf("variants: %v", v)
	}
	if v[1].Settings.RawJSON != s.RawJSON || v[1].Settings.ALPN != "" || v[1].Settings.CipherSuites != "" || !v[1].Settings.Enabled || v[2].Settings.Enabled {
		t.Fatal("wrong fallback options")
	}
	s.ALPN, s.CipherSuites = "", ""
	if len(StartupVariants(s)) != 2 {
		t.Fatal("duplicate fallback variant")
	}
	s.Enabled = false
	if len(StartupVariants(s)) != 1 {
		t.Fatal("disabled fragments should connect once")
	}
}

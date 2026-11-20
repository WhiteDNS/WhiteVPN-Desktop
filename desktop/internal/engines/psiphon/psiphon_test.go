package psiphon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/engines"
)

func build(t *testing.T, c engineprofiles.PsiphonConfig) map[string]any {
	t.Helper()
	raw, err := BuildConfig(c, "/data", 1080, 1081)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// EngineConfigBuildersTest.directPsiphonDoesNotChooseFrontedProtocols.
func TestDirectPsiphonDoesNotChooseFrontedProtocols(t *testing.T) {
	c := build(t, engineprofiles.PsiphonConfig{Mode: "direct"})
	protocols := strs(c["LimitTunnelProtocols"])
	if len(protocols) == 0 {
		t.Fatal("no protocols")
	}
	for _, p := range protocols {
		if strings.HasPrefix(p, "FRONTED-") {
			t.Fatalf("direct mode chose %s", p)
		}
	}
	if c["DisableTactics"] != true {
		t.Fatal("direct mode keeps tactics")
	}
}

func TestBuilderMatchesAndroidFields(t *testing.T) {
	c := build(t, engineprofiles.PsiphonConfig{Mode: "auto", Country: " de "})
	want := map[string]any{"PropagationChannelId": "FFFFFFFFFFFFFFFF", "SponsorId": "FFFFFFFFFFFFFFFF", "ClientVersion": "1",
		"DataRootDirectory": "/data", "LocalSocksProxyPort": 1080.0, "LocalHttpProxyPort": 1081.0, "EgressRegion": "DE",
		"EmitDiagnosticNotices": true, "FrontedMeekCDNScanUseBuiltInSpec": true, "InproxyTunnelProtocolSelectionProbability": 0.0}
	for k, v := range want {
		if !reflect.DeepEqual(c[k], v) {
			t.Errorf("%s = %#v, want %#v", k, c[k], v)
		}
	}
	if len(strs(c["LimitTunnelProtocols"])) != len(nonInproxyProtocols) || c["DisableTactics"] != nil {
		t.Fatal("auto mode must offer every non-inproxy protocol and keep tactics")
	}
	url := c["RemoteServerListURLs"].([]any)[0].(map[string]any)["URL"]
	if url != "aHR0cHM6Ly9zMy5hbWF6b25hd3MuY29tLy9wc2lwaG9uL3dlYi9tanI0LXAyM3ItcHV3bC9zZXJ2ZXJfbGlzdF9jb21wcmVzc2Vk" {
		t.Fatalf("server list URL = %v", url)
	}
	if _, ok := build(t, engineprofiles.PsiphonConfig{})["EgressRegion"]; ok {
		t.Fatal("automatic country wrote a region")
	}
}

func TestCDNModeAndFrontingOverrides(t *testing.T) {
	c := build(t, engineprofiles.PsiphonConfig{Mode: "cdn", CDNIPs: []string{"104.16.0.1", "104.16.0.0/13", "2606:4700::1", "104.16.0.1"}, CDNSNI: "HTTPS://Example.COM/path"})
	if !reflect.DeepEqual(strs(c["LimitTunnelProtocols"]), cdnProtocols) || c["DisableTactics"] != true {
		t.Fatal("cdn mode protocols")
	}
	spec := c["FrontedMeekCDNScanSpec"].(map[string]any)
	if !reflect.DeepEqual(strs(spec["IPCandidates"]), []string{"104.16.0.1", "104.16.0.0/13"}) || !reflect.DeepEqual(strs(spec["SNIServerNames"]), []string{"example.com"}) {
		t.Fatalf("scan spec = %#v", spec)
	}
	o := c["FrontedMeekDialOverrides"].([]any)[0].(map[string]any)
	if o["SNIServerName"] != "example.com" || !reflect.DeepEqual(strs(o["DialAddresses"]), []string{"104.16.0.1", "104.16.0.0/13"}) {
		t.Fatalf("override = %#v", o)
	}
	if _, ok := c["FrontedMeekCDNScanUseBuiltInSpec"]; ok {
		t.Fatal("custom IPs still use the built-in spec")
	}
	// SNI alone dials the SNI itself; IPs alone add no override.
	if o := build(t, engineprofiles.PsiphonConfig{CDNSNI: "a.example"})["FrontedMeekDialOverrides"].([]any)[0].(map[string]any); !reflect.DeepEqual(strs(o["DialAddresses"]), []string{"a.example"}) {
		t.Fatal("SNI-only dial addresses")
	}
	if _, ok := build(t, engineprofiles.PsiphonConfig{CDNIPs: []string{"1.2.3.4"}})["FrontedMeekDialOverrides"]; ok {
		t.Fatal("IP-only profile wrote an override")
	}
}

func TestCandidateParsing(t *testing.T) {
	if got := IPCandidates("1.2.3.4, 256.1.1.1;10.0.0.0/8 10.0.0.0/33\n::1"); !reflect.DeepEqual(got, []string{"1.2.3.4", "10.0.0.0/8"}) {
		t.Fatal(got)
	}
	if got := SNICandidates("http://a.b.c/x localhost ..x.y.. ünï.com"); !reflect.DeepEqual(got, []string{"a.b.c", "x.y"}) {
		t.Fatal(got)
	}
}

func TestNoticeParsing(t *testing.T) {
	cases := map[string]Notice{
		`{"noticeType":"ListeningSocksProxyPort","data":{"port":41234},"timestamp":"x"}`:          {Type: NoticeListeningSocks, Port: 41234},
		`{"noticeType":"Tunnels","data":{"count":2}}`:                                             {Type: NoticeTunnels, Count: 2},
		`{"noticeType":"AvailableEgressRegions","data":{"regions":["us"," gb","USA","DE","US"]}}`: {Type: NoticeRegions, Regions: []string{"DE", "GB", "US"}},
		`{"noticeType":"Exiting","data":{}}`:                                                      {Type: NoticeExiting},
		`{"noticeType":"SocksProxyPortInUse","data":{"port":1080}}`:                               {Type: NoticeSocksInUse, Port: 1080},
	}
	for line, want := range cases {
		got, ok := ParseNotice([]byte(line))
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v %v", line, got, ok)
		}
	}
	for _, line := range []string{`not json`, `{"noticeType":"Info","data":{"message":"x"}}`, `{"noticeType":"ListeningSocksProxyPort","data":{"port":0}}`, `{"noticeType":"Tunnels","data":{}}`} {
		if _, ok := ParseNotice([]byte(line)); ok {
			t.Errorf("%s accepted", line)
		}
	}
	if !(Notice{Type: NoticeExiting}).Fatal() || (Notice{Type: NoticeTunnels}).Fatal() {
		t.Fatal("fatal classification")
	}
}

// PsiphonRegionsTest equivalents.
func TestRegions(t *testing.T) {
	if len(KnownCodes) != 49 || len(Normalize(KnownCodes)) != 49 {
		t.Fatal("seed must hold 49 unique codes")
	}
	dir := t.TempDir()
	if got := Options(dir, " us "); got[0] != "" || len(got) != 50 {
		t.Fatalf("seed options = %v", got)
	}
	if err := Record(dir, []string{"US", "de", "bad"}); err != nil {
		t.Fatal(err)
	}
	if got := Options(dir, "XX"); !reflect.DeepEqual(got, []string{"", "DE", "US", "XX"}) {
		t.Fatalf("options = %v", got)
	}
	if got := Options(dir, "us"); !reflect.DeepEqual(got, []string{"", "DE", "US"}) {
		t.Fatalf("lowercase selection duplicated: %v", got)
	}
}

// Starts the real worker far enough to report its SOCKS port. It needs no
// internet: the port notice comes before any tunnel is attempted.
func TestWorkerReportsSOCKSPort(t *testing.T) {
	bin, _ := filepath.Abs(filepath.Join("..", "..", "..", "cores", BinaryName()))
	if _, err := os.Stat(bin); err != nil {
		t.Skip("Psiphon worker not built; run scripts/build-psiphon-engine.sh")
	}
	dir := t.TempDir()
	port, _ := engines.FreePort()
	config, _ := BuildConfig(engineprofiles.PsiphonConfig{Mode: "direct"}, filepath.Join(dir, "data"), port, 0)
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o700)
	path := filepath.Join(dir, "config.json")
	_ = os.WriteFile(path, config, 0o600)
	p := &process{configPath: path, done: make(chan struct{}), connected: make(chan struct{})}
	p.cmd = newCommand(bin, path, dir)
	stderr, _ := p.cmd.StderrPipe()
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.read(stderr, dir, func(string, ...any) {}); _ = p.cmd.Wait(); close(p.done) }()
	defer func() {
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := engines.WaitForPort(ctx, port, p.done); err != nil {
		t.Fatal(err)
	}
	for p.SOCKSPort() != port {
		select {
		case <-ctx.Done():
			t.Fatalf("reported port %d, want %d", p.SOCKSPort(), port)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

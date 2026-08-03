package main

import (
	"errors"
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestParseCloudflareTrace(t *testing.T) {
	ip, countryCode := parseCloudflareTrace([]byte("fl=abc\nip=203.0.113.10\nloc=de\nwarp=off\n"))
	if ip != "203.0.113.10" {
		t.Fatalf("unexpected IP: %q", ip)
	}
	if countryCode != "DE" {
		t.Fatalf("unexpected country code: %q", countryCode)
	}
}

func TestRuntimeSOCKSProxyAddressFallsBackToLocalhost(t *testing.T) {
	address, err := runtimeSOCKSProxyAddress(model.RuntimeStatus{
		Status:     model.RuntimeConnected,
		ListenIP:   "0.0.0.0",
		ListenPort: 10886,
	})
	if err != nil {
		t.Fatal(err)
	}
	if address != "127.0.0.1:10886" {
		t.Fatalf("unexpected proxy address: %q", address)
	}
}

func TestActiveSOCKSProxyDoesNotUseMasterDNSAuthForV2RayRuntime(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.SettingsProfiles[0].SOCKS5Authentication = true
	app.state.SettingsProfiles[0].SOCKSUsername = "user"
	app.state.SettingsProfiles[0].SOCKSPassword = "pass"
	app.state.V2RayProfiles = []model.V2RayProfile{{ID: "v2ray-1", Name: "V2Ray"}}
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		ActiveConnectionID: "v2ray-1",
		ListenIP:           "127.0.0.1",
		ListenPort:         10888,
	}

	address, auth, err := app.activeSOCKS5Proxy()
	if err != nil {
		t.Fatal(err)
	}
	if address != "127.0.0.1:10888" {
		t.Fatalf("unexpected proxy address: %q", address)
	}
	if auth != nil {
		t.Fatalf("V2Ray proxy should not inherit MasterDNS SOCKS auth, got %#v", auth)
	}
}

func TestActiveSOCKSProxyUsesMasterDNSAuthForMasterDNSRuntime(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.SettingsProfiles[0].SOCKS5Authentication = true
	app.state.SettingsProfiles[0].SOCKSUsername = "user"
	app.state.SettingsProfiles[0].SOCKSPassword = "pass"
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		ActiveConnectionID: model.DefaultConnectionProfileID,
		ListenIP:           "127.0.0.1",
		ListenPort:         10886,
	}

	_, auth, err := app.activeSOCKS5Proxy()
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil || auth.User != "user" || auth.Password != "pass" {
		t.Fatalf("expected MasterDNS SOCKS auth, got %#v", auth)
	}
}

func TestActiveProxyConfigUsesHTTPWhenRuntimeRequestsHTTP(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.SettingsProfiles[0].SOCKS5Authentication = true
	app.state.SettingsProfiles[0].SOCKSUsername = "user"
	app.state.SettingsProfiles[0].SOCKSPassword = "pass"
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		ActiveConnectionID: model.DefaultConnectionProfileID,
		ListenIP:           "127.0.0.1",
		ListenPort:         10886,
		ProxyProtocol:      "http",
	}

	cfg, err := app.activeProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "http" || cfg.Address != "127.0.0.1:10886" {
		t.Fatalf("unexpected proxy config: %#v", cfg)
	}
	if cfg.Auth == nil || cfg.Auth.User != "user" || cfg.Auth.Password != "pass" {
		t.Fatalf("expected HTTP proxy auth, got %#v", cfg.Auth)
	}
}

func TestProxyCountryCacheStoresSuccessAndErrors(t *testing.T) {
	app := &App{}
	proxyAddress := "127.0.0.1:10886"
	expected := model.ProxyCountryLookupResult{
		OK:          true,
		IP:          "203.0.113.10",
		CountryCode: "DE",
		Proxy:       proxyAddress,
	}

	app.storeProxyCountry(proxyAddress, expected, nil)
	got, err, ok := app.cachedProxyCountry(proxyAddress)
	if !ok || err != nil {
		t.Fatalf("expected cached success, ok=%t err=%v", ok, err)
	}
	if got != expected {
		t.Fatalf("unexpected cached result: %#v", got)
	}

	app.storeProxyCountry(proxyAddress, model.ProxyCountryLookupResult{Proxy: proxyAddress}, errors.New("lookup failed"))
	got, err, ok = app.cachedProxyCountry(proxyAddress)
	if !ok || err == nil || err.Error() != "lookup failed" {
		t.Fatalf("expected cached error, ok=%t result=%#v err=%v", ok, got, err)
	}

	app.clearProxyCountryCache()
	if _, _, ok := app.cachedProxyCountry(proxyAddress); ok {
		t.Fatal("expected cache to be cleared")
	}
}

package engineprofiles

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func fixture(kind Kind) Profile {
	p := Profile{Summary: Summary{ID: "4823d941-6d8a-42e2-8d23-3d181e798a05", Name: "fixture", Kind: kind, Version: 1}}
	switch kind {
	case SSH:
		p.Config.SSH = &SSHConfig{Host: "localhost", Username: "tester", Password: "test-secret"}
	case Psiphon:
		p.Config.Psiphon = &PsiphonConfig{}
	case Tor:
		p.Config.Tor = &TorConfig{}
	case DNS:
		p.Config.DNS = &DNSConfig{Domain: "tunnel.test", PublicKey: strings.Repeat("a", 64), Resolvers: []string{"127.0.0.1:5353"}}
	case AmneziaWG:
		p.Config.AmneziaWG = &AmneziaWGConfig{Raw: "[Interface]\nPrivateKey = test-secret"}
	case IKEv2:
		p.Config.IKEv2 = &IKEv2Config{Server: "vpn.test", Username: "tester", Password: "test-secret"}
	}
	return p.Defaults()
}

func TestSixKindsAndConfigIsolation(t *testing.T) {
	if len(Kinds()) != 6 {
		t.Fatal("expected six engine kinds")
	}
	for _, kind := range Kinds() {
		t.Run(string(kind), func(t *testing.T) {
			p := fixture(kind)
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(raw)
			if err != nil || decoded.Validate() != nil {
				t.Fatal("valid profile failed round trip")
			}
			p.Kind = Kind("openconnect")
			if p.Validate() == nil {
				t.Fatal("retired engine accepted")
			}
		})
	}
	p := fixture(SSH)
	p.Config.Tor = &TorConfig{}
	if p.Validate() == nil {
		t.Fatal("multiple config arms accepted")
	}
	p.Config.SSH = nil
	if p.Validate() == nil {
		t.Fatal("mismatched config accepted")
	}
}

func TestDecodeDoesNotExposeUnknownFieldOrCredential(t *testing.T) {
	for _, raw := range []string{`{"test-secret":"value"}`, `{} {}`, `{"name":"first","name":"duplicate"}`, `{"config":{"ssh":{"password":"test-secret","unexpected":"secret"}}}`, "{\"name\":\"\xff\"}", strings.Repeat("[", 18) + strings.Repeat("]", 18)} {
		_, err := Decode([]byte(raw))
		if err == nil || strings.Contains(err.Error(), "test-secret") {
			t.Fatal("invalid JSON was accepted or echoed")
		}
	}
	p := fixture(SSH)
	if strings.Contains(fmt.Sprintf("%+v %#v", p, p), "test-secret") {
		t.Fatal("profile formatting disclosed credentials")
	}
	if _, err := Decode(make([]byte, MaxProfileBytes+1)); err == nil {
		t.Fatal("oversized JSON accepted")
	}
}

func TestTorRejectsConfigurationInjection(t *testing.T) {
	p := fixture(Tor)
	p.Config.Tor.BridgeMode = "custom"
	for _, bridge := range []string{"SocksPort 0", "obfs4 127.0.0.1:443 " + strings.Repeat("a", 40) + "\nControlPort 0", "obfs4 127.0.0.1:443 " + strings.Repeat("a", 40) + " key=\"value\""} {
		p.Config.Tor.Bridges = bridge
		if p.Validate() == nil {
			t.Fatal("Tor directive accepted as bridge")
		}
	}
	p.Config.Tor.Bridges = "Bridge obfs4 127.0.0.1:443 " + strings.Repeat("a", 40) + " cert=fixture iat-mode=0\r\n"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSTransportsAndCertificateReferences(t *testing.T) {
	p := fixture(DNS)
	p.Config.DNS.Transport = "doh"
	for _, url := range []string{"http://dns.test/query", "https://user:password@dns.test/query", "https://dns.test/query#fragment"} {
		p.Config.DNS.DoHURL = url
		if p.Validate() == nil {
			t.Fatal("unsafe DoH URL accepted")
		}
	}
	p.Config.DNS.DoHURL = "https://dns.test/query"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Config.DNS.Engine = "masterdns"
	if p.Validate() == nil {
		t.Fatal("MasterDNS accepted DoH")
	}
	p = fixture(IKEv2)
	p.Config.IKEv2.AuthType = "certificate"
	p.Config.IKEv2.CertificateThumbprint = strings.Repeat("ab", 20)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Config.IKEv2.CertificateStore = "arbitrary-store"
	if p.Validate() == nil {
		t.Fatal("arbitrary certificate store accepted")
	}
}

func TestDefaultsPreserveSecretsAndClone(t *testing.T) {
	p := fixture(SSH)
	p.Config.SSH.Password = "  keep spaces\n"
	copy := p.Defaults()
	if copy.Config.SSH.Password != p.Config.SSH.Password {
		t.Fatal("credential normalized")
	}
	copy.Config.SSH.Password = "changed"
	if p.Config.SSH.Password == "changed" {
		t.Fatal("editor aliases original")
	}
}

func TestRouteUnionAndPolicy(t *testing.T) {
	for _, r := range []RouteRef{{Kind: "engine", ProfileID: fixture(SSH).ID, SourceID: "all"}, {Kind: "mihomo", SourceID: "all", ProfileID: fixture(SSH).ID}, {Kind: "unknown"}} {
		if r.Validate() == nil {
			t.Fatal("invalid route union accepted")
		}
	}
	if err := (RouteRef{Kind: "mihomo", SourceID: "all"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (RouteRef{Kind: "engine", ProfileID: fixture(SSH).ID}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range Kinds() {
		c := Policy(kind)
		if c.Chain || c.LAN || (kind.SOCKS() && c.UDP) {
			t.Fatal("unsupported capability enabled")
		}
		if !kind.SOCKS() && (c.Proxy || c.AppSplit || c.CustomDNS) {
			t.Fatal("native inherited proxy policy")
		}
	}
}

package profiles

import (
	"testing"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
)

func TestImportAnyTLSLink(t *testing.T) {
	profiles, err := ParseV2RayProfileImports("anytls://sw0rdf1sh@node.example.com:8443/?sni=node.example.com&insecure=1&alpn=h2,http/1.1&hpkp=deadbeef#DE%20One")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one profile, got %d", len(profiles))
	}
	profile := profiles[0]
	for _, check := range []struct {
		field string
		got   any
		want  any
	}{
		{"protocol", profile.Protocol, model.V2RayProtocolAnyTLS},
		{"name", profile.Name, "DE One"},
		{"server", profile.Server, "node.example.com"},
		{"port", profile.ServerPort, 8443},
		{"password", profile.Password, "sw0rdf1sh"},
		{"sni", profile.SNI, "node.example.com"},
		{"alpn", profile.ALPN, "h2,http/1.1"},
		{"allowInsecure", profile.AllowInsecure, true},
		{"certFingerprint", profile.CertFingerprint, "deadbeef"},
		{"tls", profile.TLS, true},
	} {
		if check.got != check.want {
			t.Errorf("%s = %#v, want %#v", check.field, check.got, check.want)
		}
	}
}

// The same reading mihomoconf uses. Two importers disagreeing about which half
// of the user info is the secret would mean a link that connects out of a
// subscription and fails when pasted.
func TestImportAnyTLSTakesThePasswordHalfOfAUserPassPair(t *testing.T) {
	profiles, err := ParseV2RayProfileImports("anytls://user:s3cret@node.example.com:443#Pair")
	if err != nil {
		t.Fatal(err)
	}
	if profiles[0].Password != "s3cret" {
		t.Fatalf("password = %q, want %q", profiles[0].Password, "s3cret")
	}
}

func TestImportAnyTLSWithoutAPasswordIsRefused(t *testing.T) {
	if _, err := ParseV2RayProfileImports("anytls://node.example.com:443#Bare"); err == nil {
		t.Fatal("expected a link with no password to be refused")
	}
}

// Manual configs reach the engine by being exported back to links and read by
// mihomoconf, so anything the export drops is dropped from the connection.
func TestAnyTLSSurvivesTheExportRoundTrip(t *testing.T) {
	imported, err := ParseV2RayProfileImports("anytls://pa%3Assword@node.example.com:8443/?sni=front.example.com&insecure=1&hpkp=deadbeef&fp=chrome#Round%20Trip")
	if err != nil {
		t.Fatal(err)
	}
	link, err := ExportV2RayProfile(imported[0])
	if err != nil {
		t.Fatal(err)
	}

	again, err := ParseV2RayProfileImports(link)
	if err != nil {
		t.Fatalf("re-import %q: %v", link, err)
	}
	got, want := again[0], imported[0]
	got.ID, want.ID = "", ""
	if got != want {
		t.Fatalf("round trip changed the profile:\n got %#v\nwant %#v\nlink %s", got, want, link)
	}
	if want.Password != "pa:ssword" {
		t.Fatalf("password = %q, want %q", want.Password, "pa:ssword")
	}
}

// The pin is the whole of the protection an hpkp link is asking for. Dropping
// it on the way out would leave a connection that verified when it was imported
// and stopped verifying afterwards.
func TestExportedAnyTLSLinkIsReadByTheEngineConverter(t *testing.T) {
	imported, err := ParseV2RayProfileImports("anytls://secret@node.example.com:8443/?sni=front.example.com&hpkp=deadbeef#Engine")
	if err != nil {
		t.Fatal(err)
	}
	body, err := ExportV2RayProfiles(imported)
	if err != nil {
		t.Fatal(err)
	}

	proxies, err := mihomoconf.ConvertLinks(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one proxy from %q, got %d", body, len(proxies))
	}
	proxy := proxies[0]
	if proxy["type"] != "anytls" || proxy["password"] != "secret" ||
		proxy["sni"] != "front.example.com" || proxy["fingerprint"] != "deadbeef" {
		t.Fatalf("engine converter read %#v", proxy)
	}
}

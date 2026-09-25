package mihomoconf

import (
	"strings"
	"testing"
)

func amneziaOptionsFor(t *testing.T, query string) map[string]any {
	t.Helper()
	proxies, err := ConvertLinks("wireguard://k%3D@1.2.3.4:51820?publickey=p%3D&" + query + "#N")
	if err != nil {
		t.Fatal(err)
	}
	options, _ := proxies[0]["amnezia-wg-option"].(map[string]any)
	return options
}

// v3 builds a different WireGuard device from the legacy one, and each rejects
// the other's keys outright — which fails the whole configuration, not this one
// proxy. So a link carrying both has to be settled before it is sent on.
func TestVersionThreeDropsTheFieldsRemovedInVersionTwo(t *testing.T) {
	options := amneziaOptionsFor(t, "version=3&jc=4&j1=aa&j2=bb&j3=cc&itime=30&header-protection-key=a2V5")
	if options["version"] != 3 {
		t.Fatalf("version was not carried: %#v", options)
	}
	for _, gone := range []string{"j1", "j2", "j3", "itime"} {
		if _, present := options[gone]; present {
			t.Errorf("%s is v1.5-only and cannot travel with version 3", gone)
		}
	}
	// What both versions share must survive.
	if options["jc"] != 4 {
		t.Errorf("jc belongs to both and should have been kept: %#v", options)
	}
	if options["header-protection-key"] != "a2V5" {
		t.Errorf("the v3 field was lost: %#v", options)
	}
}

// The mirror: on the legacy device the v3 parameters are keys it has never
// heard of.
func TestTheLegacyDeviceDoesNotGetVersionThreeFields(t *testing.T) {
	options := amneziaOptionsFor(t, "jc=4&j1=aa&itime=30")
	for _, absent := range []string{"header-protection-key", "random-trailers", "version"} {
		if _, present := options[absent]; present {
			t.Errorf("%s should not appear on a link that never mentioned version 3: %#v", absent, options)
		}
	}
	if options["j1"] != "aa" || options["itime"] != 30 {
		t.Errorf("the v1.5 fields belong here and were dropped: %#v", options)
	}
}

// These parameters exist nowhere but v3, so carrying them is the same statement
// as declaring it. Reading them any other way leaves a link that means nothing.
func TestVersionThreeIsInferredFromItsOwnFields(t *testing.T) {
	options := amneziaOptionsFor(t, "jc=4&rekey-after-time=120&random-trailers=true")
	if options["version"] != 3 {
		t.Fatalf("v3-only fields should imply version 3: %#v", options)
	}
	if options["rekey-after-time"] != "120" || options["random-trailers"] != true {
		t.Fatalf("the v3 fields were not kept: %#v", options)
	}
}

// A plain link stays plain — inference must not manufacture a version.
func TestNoVersionIsInventedForOrdinaryAmneziaLinks(t *testing.T) {
	options := amneziaOptionsFor(t, "jc=4&jmin=40&jmax=70")
	if _, present := options["version"]; present {
		t.Fatalf("nothing here says v3: %#v", options)
	}
}

// The underscore spellings other clients emit.
func TestTheV3LongSpellingsAreRead(t *testing.T) {
	options := amneziaOptionsFor(t, "version=3&header_protection_key=a2V5&max_handshake_attempts=5&disable_cookies=1")
	if options["header-protection-key"] != "a2V5" || options["max-handshake-attempts"] != "5" {
		t.Fatalf("underscore spellings were not read: %#v", options)
	}
	if options["disable-cookies"] != true {
		t.Fatalf("1 should read as true: %#v", options)
	}
}

// Every key emitted has to exist in the core, in both directions, or one unknown
// key fails every WireGuard proxy in the subscription.
func TestTheEmittedKeysMatchTheCoreExactly(t *testing.T) {
	emitted := map[string]bool{"version": true}
	for _, set := range []map[string][]string{amneziaIntFields, amneziaStringFields, amneziaV3Fields, amneziaV3BoolFields} {
		for field := range set {
			emitted[field] = true
		}
	}
	// v1.19.30's AmneziaWGOption, field for field.
	core := strings.Fields(`version jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4
		i1 i2 i3 i4 i5 j1 j2 j3 itime
		header-protection-key content-padding-addition rekey-after-time rekey-timeout
		reject-after-time keepalive-timeout max-handshake-attempts random-trailers disable-cookies`)
	for _, field := range core {
		if !emitted[field] {
			t.Errorf("%s is in the core and never read from a link", field)
		}
		delete(emitted, field)
	}
	for field := range emitted {
		t.Errorf("%s is emitted and the core has no field for it", field)
	}
}

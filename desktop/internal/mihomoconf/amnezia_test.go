package mihomoconf

import (
	"reflect"
	"strings"
	"testing"
)

const amneziaLink = "wireguard://oPrivateKey123%3D@1.2.3.4:51820" +
	"?publickey=oPublicKey456%3D&address=10.0.0.2/32" +
	"&jc=4&jmin=40&jmax=70&s1=15&s2=25&h1=1234567890&h2=987654321#AmneziaNode"

// The parameters a server disguising its handshake requires. They were read as
// far as the keys and then dropped, so the node imported, listed, and could
// never connect.
func TestAnAmneziaLinkKeepsItsParameters(t *testing.T) {
	proxies, err := ConvertLinks(amneziaLink)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one proxy, got %d", len(proxies))
	}

	options, ok := proxies[0]["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatalf("the link's Amnezia parameters were dropped: %#v", proxies[0])
	}
	want := map[string]any{
		"jc": 4, "jmin": 40, "jmax": 70, "s1": 15, "s2": 25,
		"h1": "1234567890", "h2": "987654321",
	}
	if !reflect.DeepEqual(options, want) {
		t.Fatalf("parameters do not match:\n got %#v\nwant %#v", options, want)
	}
}

// An empty amnezia-wg-option is not the same as none: it would turn every plain
// WireGuard proxy into an AmneziaWG one running all the defaults, which no
// server is expecting.
func TestAPlainWireGuardLinkStaysPlain(t *testing.T) {
	plain := "wireguard://oPrivateKey123%3D@1.2.3.4:51820?publickey=oPublicKey456%3D&address=10.0.0.2/32#Plain"
	proxies, err := ConvertLinks(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := proxies[0]["amnezia-wg-option"]; present {
		t.Fatalf("a plain link should carry no Amnezia options: %#v", proxies[0])
	}
}

// Zero is a legal instruction — jc=0 means no junk packets — so it has to
// survive, while a value that will not parse must be dropped rather than become
// a zero nobody asked for.
func TestZeroIsKeptAndNonsenseIsDropped(t *testing.T) {
	link := "wireguard://k%3D@1.2.3.4:51820?publickey=p%3D&jc=0&jmin=abc&jmax=-5#Edge"
	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	options, ok := proxies[0]["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatalf("jc=0 is a parameter and should have been kept: %#v", proxies[0])
	}
	if got, present := options["jc"]; !present || got != 0 {
		t.Errorf("jc=0 should survive, got %v (present=%v)", got, present)
	}
	if _, present := options["jmin"]; present {
		t.Error("jmin=abc is not a number and must not become one")
	}
	if _, present := options["jmax"]; present {
		t.Error("a negative jmax must not be accepted")
	}
}

// The long spellings other clients emit.
func TestTheLongerSpellingsAreRead(t *testing.T) {
	link := "wireguard://k%3D@1.2.3.4:51820?publickey=p%3D" +
		"&junk_packet_count=3&init_packet_junk_size=12&init_packet_magic_header=555#Long"
	proxies, err := ConvertLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	options, _ := proxies[0]["amnezia-wg-option"].(map[string]any)
	if options["jc"] != 3 || options["s1"] != 12 || options["h1"] != "555" {
		t.Fatalf("long spellings were not read: %#v", options)
	}
}

// The setting exists for nodes that arrived without parameters. A server's own
// are part of its address, and a different server's numbers written over them
// produce a handshake nobody answers.
func TestTheGlobalSettingDoesNotOverwriteALinksOwn(t *testing.T) {
	proxies, err := ConvertLinks(amneziaLink)
	if err != nil {
		t.Fatal(err)
	}
	noised, changed := ApplyAmneziaNoise(proxies, AmneziaNoise{Enabled: true, Count: 9, MinSize: 90, MaxSize: 99})

	options, _ := noised[0]["amnezia-wg-option"].(map[string]any)
	if options["jc"] != 4 || options["jmin"] != 40 {
		t.Fatalf("the link's own parameters were overwritten: %#v", options)
	}
	if changed != 0 {
		t.Errorf("nothing was changed, so the count should be 0, got %d", changed)
	}
}

// And it still reaches a node that has none.
func TestTheGlobalSettingStillReachesPlainNodes(t *testing.T) {
	plain := "wireguard://k%3D@1.2.3.4:51820?publickey=p%3D#Plain"
	proxies, err := ConvertLinks(plain)
	if err != nil {
		t.Fatal(err)
	}
	noised, changed := ApplyAmneziaNoise(proxies, AmneziaNoise{Enabled: true, Count: 9, MinSize: 90, MaxSize: 99})
	options, ok := noised[0]["amnezia-wg-option"].(map[string]any)
	if !ok || options["jc"] != 9 {
		t.Fatalf("the setting should have applied here: %#v", noised[0])
	}
	if changed != 1 {
		t.Errorf("expected one proxy changed, got %d", changed)
	}
}

// mihomo decodes this map into a struct and rejects keys it has no field for, so
// one unknown key fails every WireGuard proxy in the subscription, not just this
// one. Whatever is emitted has to exist in the pinned core.
func TestOnlyFieldsThePinnedCoreKnowsAreEmitted(t *testing.T) {
	known := map[string]bool{}
	for _, set := range []map[string][]string{amneziaIntFields, amneziaStringFields} {
		for field := range set {
			known[field] = true
		}
	}
	// v1.19.29's AmneziaWGOption, field for field.
	for _, field := range strings.Fields("jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 j1 j2 j3 itime") {
		if !known[field] {
			t.Errorf("%s is in the core and not read from links", field)
		}
		delete(known, field)
	}
	for field := range known {
		t.Errorf("%s is emitted but the pinned core has no field for it", field)
	}
}

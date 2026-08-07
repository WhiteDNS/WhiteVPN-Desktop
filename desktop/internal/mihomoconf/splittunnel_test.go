package mihomoconf

import (
	"strings"
	"testing"
)

func ruleStrings(t *testing.T, document string) []string {
	t.Helper()
	parsed := parseYAML(t, document)
	raw, _ := parsed["rules"].([]any)
	rules := make([]string, 0, len(raw))
	for _, rule := range raw {
		rules = append(rules, rule.(string))
	}
	return rules
}

// The report that started this: a program added to the bypass list, and the
// site it was meant to reach still saw the VPN's address — because nothing
// outside the model ever read the setting.
func TestBypassSendsNamedProgramsDirect(t *testing.T) {
	document, err := BuildProxiesYAML(sampleProxies(t), SplitTunnel{
		Mode:      SplitTunnelBypass,
		Processes: []string{"chrome.exe", "steam.exe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := ruleStrings(t, document)

	if len(rules) != 3 {
		t.Fatalf("expected two process rules and the catch-all, got %#v", rules)
	}
	if rules[0] != "PROCESS-NAME,chrome.exe,DIRECT" || rules[1] != "PROCESS-NAME,steam.exe,DIRECT" {
		t.Fatalf("unexpected process rules: %#v", rules)
	}
	// mihomo takes the first rule that fits, so a catch-all above these would
	// mean neither is ever reached.
	if rules[2] != "MATCH,"+SelectGroup {
		t.Fatalf("the catch-all must come last: %#v", rules)
	}
}

func TestVPNOnlySendsEverythingElseDirect(t *testing.T) {
	document, err := BuildProxiesYAML(sampleProxies(t), SplitTunnel{
		Mode:      SplitTunnelOnly,
		Processes: []string{"chrome.exe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := ruleStrings(t, document)

	if len(rules) != 2 {
		t.Fatalf("expected the process rule and a direct catch-all, got %#v", rules)
	}
	if rules[0] != "PROCESS-NAME,chrome.exe,"+SelectGroup {
		t.Fatalf("the named program should go through the group: %#v", rules)
	}
	// And this is what makes the mode mean what it says. Two catch-alls would
	// leave a dead one saying everything is tunnelled — the line someone reading
	// the config to answer "why is this not tunnelled" would stop at.
	if rules[1] != "MATCH,DIRECT" {
		t.Fatalf("everything else should go direct: %#v", rules)
	}
	for _, rule := range rules {
		if rule == "MATCH,"+SelectGroup {
			t.Fatalf("the tunnelling catch-all should not be there too: %#v", rules)
		}
	}
}

// Naming nothing must not change the routing. Read literally, vpn-only with an
// empty list says "send nothing through the tunnel" — which would turn the VPN
// off while the interface still said Connected.
func TestSplitTunnelWithNoProgramsChangesNothing(t *testing.T) {
	for _, mode := range []SplitTunnelMode{SplitTunnelBypass, SplitTunnelOnly} {
		document, err := BuildProxiesYAML(sampleProxies(t), SplitTunnel{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		rules := ruleStrings(t, document)
		if len(rules) != 1 || rules[0] != "MATCH,"+SelectGroup {
			t.Fatalf("%s with no programs should route normally, got %#v", mode, rules)
		}
	}
}

func TestSplitTunnelOffRoutesEverythingThroughTheTunnel(t *testing.T) {
	document, err := BuildProxiesYAML(sampleProxies(t), SplitTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	rules := ruleStrings(t, document)
	if len(rules) != 1 || rules[0] != "MATCH,"+SelectGroup {
		t.Fatalf("unexpected rules: %#v", rules)
	}
}

// A name with a comma would be read as extra fields and change what the rule
// means; a blank one matches nothing and is only noise in a config someone has
// to read when something goes wrong.
func TestSplitTunnelDropsNamesThatWouldNotBeRules(t *testing.T) {
	split := SplitTunnel{
		Mode:      SplitTunnelBypass,
		Processes: []string{" chrome.exe ", "", "  ", "bad,name.exe", "with\nnewline", "CHROME.EXE", "steam.exe"},
	}
	rules := split.Rules(SelectGroup)

	if len(rules) != 2 {
		t.Fatalf("expected chrome and steam only, got %#v", rules)
	}
	if rules[0] != "PROCESS-NAME,chrome.exe,DIRECT" {
		t.Fatalf("the name should be trimmed: %#v", rules)
	}
	if rules[1] != "PROCESS-NAME,steam.exe,DIRECT" {
		t.Fatalf("expected steam second: %#v", rules)
	}
}

// Looking up which program owns a connection costs something per connection, so
// it is only asked for when a rule needs the answer.
func TestFindProcessModeFollowsTheSplitTunnel(t *testing.T) {
	off := Render("", Options{Secret: "s", ProxyGroup: SelectGroup})
	if !strings.Contains(off, "find-process-mode: off") {
		t.Fatal("with no split tunnel the engine should not look processes up")
	}

	on := Render("", Options{
		Secret:      "s",
		ProxyGroup:  SelectGroup,
		SplitTunnel: SplitTunnel{Mode: SplitTunnelBypass, Processes: []string{"chrome.exe"}},
	})
	if !strings.Contains(on, "find-process-mode: strict") {
		t.Fatal("a split tunnel needs process lookup or its rules never fire")
	}

	// And a mode with nothing named is not a split tunnel.
	empty := Render("", Options{
		Secret:      "s",
		ProxyGroup:  SelectGroup,
		SplitTunnel: SplitTunnel{Mode: SplitTunnelBypass},
	})
	if !strings.Contains(empty, "find-process-mode: off") {
		t.Fatal("naming nothing should not turn process lookup on")
	}
}

// A subscription carrying its own find-process-mode must not override the app's.
func TestRenderStripsASubscriptionsFindProcessMode(t *testing.T) {
	document := Render("find-process-mode: always\nproxies: []\n", Options{Secret: "s", ProxyGroup: SelectGroup})
	if strings.Contains(document, "find-process-mode: always") {
		t.Fatalf("the subscription's value should have been stripped:\n%s", document)
	}
}

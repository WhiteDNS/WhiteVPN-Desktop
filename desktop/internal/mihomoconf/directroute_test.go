package mihomoconf

import (
	"strings"
	"testing"
)

// What somebody types is not what mihomo matches, and every one of these would
// otherwise match nothing at all while looking perfectly reasonable in the list.
func TestWhatSomebodyTypedBecomesWhatMihomoMatches(t *testing.T) {
	cases := []struct {
		typed string
		want  string
	}{
		{"digikala.com", "digikala.com"},
		{"  aparat.com  ", "aparat.com"},
		{".ir", "ir"},
		{"IR", "ir"},
		{"https://www.bank.ir/login", "www.bank.ir"},
		{"example.com:443", "example.com"},
		{"http://example.com", "example.com"},
	}
	for _, tc := range cases {
		got := cleanDomains([]string{tc.typed})
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%q became %v, want [%q]", tc.typed, got, tc.want)
		}
	}
}

// Blank entries are what a textarea produces; duplicates are what pasting a
// list twice produces. Neither should reach the engine.
func TestEmptyAndRepeatedEntriesAreDropped(t *testing.T) {
	got := cleanDomains([]string{"ir", "", "  ", "ir", ".IR", "example.com"})
	if len(got) != 2 || got[0] != "ir" || got[1] != "example.com" {
		t.Fatalf("got %v, want [ir example.com]", got)
	}
}

// Typing /32 after an address is a step people forget, and an error message
// about it teaches nothing they wanted to know.
func TestABareAddressGetsItsOwnMask(t *testing.T) {
	got := cleanIPs([]string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1", "  "})
	want := []string{"1.2.3.4/32", "10.0.0.0/8", "2001:db8::1/128"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Addresses before names, because an IP rule can be answered without resolving
// anything and mihomo takes the first rule that fits.
func TestAddressRulesComeBeforeNameRules(t *testing.T) {
	rules := DirectRoute{Domains: []string{"ir"}, IPs: []string{"10.0.0.0/8"}}.Rules()
	if len(rules) != 2 {
		t.Fatalf("expected two rules, got %v", rules)
	}
	if !strings.HasPrefix(rules[0], "IP-CIDR,") {
		t.Fatalf("the address rule should come first: %v", rules)
	}
	if !strings.HasPrefix(rules[1], "DOMAIN-SUFFIX,") {
		t.Fatalf("the name rule should come second: %v", rules)
	}
}

// Without no-resolve every request would resolve before routing, which both
// slows things down and hands the name to whichever resolver answered — the
// leak this app closes elsewhere.
func TestAddressRulesDoNotResolveNames(t *testing.T) {
	rules := DirectRoute{IPs: []string{"10.0.0.0/8"}}.Rules()
	if len(rules) != 1 || !strings.HasSuffix(rules[0], ",no-resolve") {
		t.Fatalf("expected a no-resolve address rule, got %v", rules)
	}
}

// Nothing configured has to mean no rules, so that switching this off produces
// the same document as never having switched it on.
func TestNothingConfiguredProducesNoRules(t *testing.T) {
	for _, route := range []DirectRoute{
		{},
		{Domains: []string{"", "   "}},
		{IPs: []string{""}},
	} {
		if route.Active() {
			t.Errorf("%#v should not be active", route)
		}
		if rules := route.Rules(); len(rules) != 0 {
			t.Errorf("%#v produced %v", route, rules)
		}
	}
}

// The ordering that decides what this feature actually does.
//
// Under "only these programs are tunnelled" the split tunnel writes
// MATCH,DIRECT last and a PROCESS-NAME rule pointing at the group first. If the
// direct rules came after that process rule, a tunnelled program's Iranian
// traffic would go through the tunnel anyway — which is the one case somebody
// turning this on is trying to prevent.
func TestDirectRulesAreMatchedBeforeTheSplitTunnel(t *testing.T) {
	document, _, err := BuildProxiesYAMLWithRouting(chainProxies(), Routing{
		Direct: DirectRoute{Domains: []string{"ir"}},
		Split:  SplitTunnel{Mode: SplitTunnelOnly, Processes: []string{"firefox.exe"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	directAt := strings.Index(document, "DOMAIN-SUFFIX,ir,DIRECT")
	processAt := strings.Index(document, "PROCESS-NAME,firefox.exe")
	if directAt < 0 || processAt < 0 {
		t.Fatalf("both rules should be present:\n%s", document)
	}
	if directAt > processAt {
		t.Fatalf("the direct rule must be matched first:\n%s", document)
	}
}

// And the catch-all stays last, or nothing above it is ever reached.
func TestTheCatchAllIsStillLast(t *testing.T) {
	document, _, err := BuildProxiesYAMLWithRouting(chainProxies(), Routing{
		Direct: DirectRoute{Domains: []string{"ir"}, IPs: []string{"10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	matchAt := strings.LastIndex(document, "MATCH,")
	for _, rule := range []string{"DOMAIN-SUFFIX,ir,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"} {
		at := strings.Index(document, rule)
		if at < 0 {
			t.Fatalf("%s is missing:\n%s", rule, document)
		}
		if at > matchAt {
			t.Fatalf("%s comes after the catch-all, so it can never match:\n%s", rule, document)
		}
	}
}

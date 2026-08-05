package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"whitevpn-desktop/internal/mihomoconf"
)

const sampleLinks = "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=reality&pbk=k&sid=00#Alpha\n" +
	"trojan://password@b.example.com:443?sni=b.example.com#Beta"

func TestPrepareConfigFromShareLinks(t *testing.T) {
	document, candidates, err := PrepareConfig(Options{Subscription: sampleLinks, Tun: mihomoconf.DefaultTunOptions()})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 selectable nodes, got %v", candidates)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}
	// Links carry nodes only, so the group and rule have to have been generated.
	if _, present := parsed["proxy-groups"]; !present {
		t.Fatal("share links should have gained groups")
	}
	if parsed["dns"].(map[string]any)["respect-rules"] != true {
		t.Fatal("DNS should resolve through the generated group")
	}
}

// A mihomo document already has its own groups and rules, and rewriting them
// would override choices the provider made deliberately.
func TestPrepareConfigPassesMihomoYAMLThrough(t *testing.T) {
	subscription := strings.Join([]string{
		"proxies:",
		"  - name: Node",
		"    type: trojan",
		"    server: a.example.com",
		"    port: 443",
		"    password: pw",
		"proxy-groups:",
		"  - name: Provider Group",
		"    type: select",
		"    proxies: ['Node']",
		"rules:",
		"  - MATCH,Provider Group",
	}, "\n")

	document, candidates, err := PrepareConfig(Options{Subscription: subscription})
	if err != nil {
		t.Fatal(err)
	}
	// A provider's document selects its own node, so there is nothing for us to
	// choose between and nothing to override.
	if len(candidates) != 0 {
		t.Fatalf("expected no candidates for a provider document, got %v", candidates)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatal(err)
	}
	groups := parsed["proxy-groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["name"] != "Provider Group" {
		t.Fatalf("provider groups should survive untouched: %#v", groups)
	}
	// DNS must resolve through a group that exists, which here is theirs.
	dns := parsed["dns"].(map[string]any)
	servers := dns["nameserver"].([]any)
	if !strings.HasSuffix(servers[0].(string), "#Provider Group") {
		t.Fatalf("DNS should follow the provider's group: %#v", servers[0])
	}
}

func TestPrepareConfigRejectsUnusableInput(t *testing.T) {
	for _, subscription := range []string{"", "   ", "this is not a subscription"} {
		if _, _, err := PrepareConfig(Options{Subscription: subscription}); err == nil {
			t.Fatalf("expected %q to be rejected", subscription)
		}
	}
}

// The dashboard's location and connection choices arrive as Prefer. They narrow
// what an attempt reaches for; they never narrow the configuration itself, so a
// later choice needs no reconnect.
func TestPrepareConfigHonoursPreferredNodes(t *testing.T) {
	document, candidates, err := PrepareConfig(Options{
		Subscription: sampleLinks,
		Prefer:       []string{"Beta"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0] != "Beta" {
		t.Fatalf("expected only the preferred node to be tried, got %v", candidates)
	}
	if !strings.Contains(document, "Alpha") {
		t.Fatal("the node not preferred should still be in the config, only not reached for")
	}
}

func TestPrepareConfigKeepsThePreferredOrder(t *testing.T) {
	_, candidates, err := PrepareConfig(Options{
		Subscription: sampleLinks,
		// Reversed, and naming one node the subscription does not have.
		Prefer: []string{"Beta", "Gone", "Alpha"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0] != "Beta" || candidates[1] != "Alpha" {
		t.Fatalf("expected the preferred order minus what is missing, got %v", candidates)
	}
}

// Silently connecting elsewhere would tell a user their traffic leaves from a
// country it does not.
func TestPrepareConfigRefusesAPreferenceNothingMatches(t *testing.T) {
	_, _, err := PrepareConfig(Options{Subscription: sampleLinks, Prefer: []string{"Gone"}})
	if err == nil {
		t.Fatal("expected a preference matching nothing to be refused")
	}
}

// Each run gets its own control secret; a fixed one would let any local process
// that knows it drive the engine.
func TestEachConfigGetsItsOwnSecret(t *testing.T) {
	first, _, err := PrepareConfig(Options{Subscription: sampleLinks})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := PrepareConfig(Options{Subscription: sampleLinks})
	if err != nil {
		t.Fatal(err)
	}
	if secretOf(first) == secretOf(second) {
		t.Fatal("two configs share a control secret")
	}
}

func secretOf(document string) string {
	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, "secret:") {
			return line
		}
	}
	return ""
}

func TestWaitForHealthyAcceptsTheFirstGoodStatus(t *testing.T) {
	attempts := 0
	code, err := waitForHealthy(context.Background(), func(context.Context) int {
		attempts++
		if attempts < 3 {
			return -1
		}
		return 204
	})
	if err != nil {
		t.Fatalf("expected success once the proxy answered: %v", err)
	}
	if code != 204 || attempts != 3 {
		t.Fatalf("code %d after %d attempts", code, attempts)
	}
}

// The engine needs a moment after startListener, so the check must keep trying
// rather than give up on one failure — but it must also stop eventually instead
// of leaving a user watching a spinner for ever.
func TestWaitForHealthyGivesUpWithinItsBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	if _, err := waitForHealthy(ctx, func(context.Context) int { return -1 }); err == nil {
		t.Fatal("expected failure when nothing ever answers")
	}
	if elapsed := time.Since(start); elapsed > healthBudget {
		t.Fatalf("waited %s, longer than the %s budget", elapsed, healthBudget)
	}
}

func TestWaitForHealthyStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := waitForHealthy(ctx, func(context.Context) int { return -1 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation to propagate, got %v", err)
	}
}

func TestHealthyStatusRange(t *testing.T) {
	for _, code := range []int{200, 204, 301, 399} {
		if !healthy(code) {
			t.Fatalf("%d should count as healthy", code)
		}
	}
	for _, code := range []int{-1, 0, 199, 400, 403, 500} {
		if healthy(code) {
			t.Fatalf("%d should not count as healthy", code)
		}
	}
}

func TestDetectProxyGroupPrefersOurOwn(t *testing.T) {
	document := strings.Join([]string{
		"proxy-groups:",
		"  - name: Their Group",
		"    type: select",
		"  - name: " + mihomoconf.SelectGroup,
		"    type: select",
	}, "\n")
	if group := detectProxyGroup(document); group != mihomoconf.SelectGroup {
		t.Fatalf("expected our own group to win, got %q", group)
	}
}

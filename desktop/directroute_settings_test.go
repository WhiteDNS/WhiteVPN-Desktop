package main

import (
	"strings"
	"testing"

	"whitevpn-desktop/internal/model"
)

// Switching it off has to produce the same configuration as never having
// switched it on, or somebody comparing two connections is comparing documents
// that differ for no reason.
func TestDirectRoutingOffKeepsTheListsButWritesNoRules(t *testing.T) {
	settings := model.WhiteVPNSettings{
		DirectRouting: model.DirectRoutingSettings{
			Enabled: false,
			Domains: []string{"ir", "digikala.com"},
			IPs:     []string{"10.0.0.0/8"},
		},
	}
	route := directRouteFor(settings)
	if route.Active() {
		t.Fatal("the lists should not reach the engine while the switch is off")
	}
	// And the lists themselves survive, which is what makes turning it off
	// worth doing rather than clearing them.
	if len(settings.DirectRouting.Domains) != 2 {
		t.Fatal("the saved list was modified by reading it")
	}
}

func TestDirectRoutingOnCarriesBothLists(t *testing.T) {
	route := directRouteFor(model.WhiteVPNSettings{
		DirectRouting: model.DirectRoutingSettings{
			Enabled: true,
			Domains: []string{"ir"},
			IPs:     []string{"10.0.0.0/8"},
		},
	})
	if !route.Active() {
		t.Fatal("expected the route to be active")
	}
	rules := strings.Join(route.Rules(), "\n")
	for _, want := range []string{"DOMAIN-SUFFIX,ir,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in:\n%s", want, rules)
		}
	}
}

// The starting list is off, so an update cannot change where anybody's traffic
// goes without them choosing it.
func TestTheStartingListIsOffButNotEmpty(t *testing.T) {
	defaults := model.DefaultDirectRouting()
	if defaults.Enabled {
		t.Fatal("shipping this on would reroute traffic nobody asked to reroute")
	}
	if len(defaults.Domains) == 0 {
		t.Fatal("an empty list behind a switch teaches nobody what the switch is for")
	}
	// ".ir" is the entry that earns its place without any database at all.
	found := false
	for _, domain := range defaults.Domains {
		if domain == "ir" {
			found = true
		}
	}
	if !found {
		t.Fatal(`"ir" covers the whole .ir top-level domain and should be there`)
	}
}

// A settings file edited by hand, or one carried from an older version, must
// not be able to put blanks or repeats in front of the engine.
func TestHandEditedListsAreTidiedOnLoad(t *testing.T) {
	got := model.NormalizeWhiteVPNSettings(model.WhiteVPNSettings{
		DirectRouting: model.DirectRoutingSettings{
			Enabled: true,
			Domains: []string{"IR", " ", "ir", "digikala.com", ""},
			IPs:     []string{"10.0.0.0/8", "", "10.0.0.0/8"},
		},
	})
	if len(got.DirectRouting.Domains) != 2 {
		t.Fatalf("domains were not tidied: %v", got.DirectRouting.Domains)
	}
	if len(got.DirectRouting.IPs) != 1 {
		t.Fatalf("addresses were not tidied: %v", got.DirectRouting.IPs)
	}
}

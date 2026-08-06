//go:build darwin

package sysproxy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The two platforms spell the same bypass list differently. The stored state
// keeps the Windows spelling, so the translation has to happen on the way out.
func TestBypassDomainsTranslatesTheStoredList(t *testing.T) {
	got := bypassDomains(DefaultBypass)
	if len(got) == 0 {
		t.Fatal("the bypass list must not come out empty")
	}
	for _, entry := range got {
		if entry == "<local>" {
			// A Windows token with no meaning to networksetup; the wildcards
			// beside it already cover it.
			t.Fatal("<local> is a Windows token and must not be passed to networksetup")
		}
	}
	if got[0] != "localhost" {
		t.Fatalf("expected the list to keep its order, got %#v", got)
	}
}

// networksetup needs an argument. "Empty" is its own word for "no bypasses",
// and passing nothing at all is an error rather than a clear list.
func TestBypassDomainsNeverPassesNothing(t *testing.T) {
	if got := bypassDomains(""); !reflect.DeepEqual(got, []string{"Empty"}) {
		t.Fatalf("bypassDomains(\"\") = %#v, want [Empty]", got)
	}
	if got := bypassDomains("<local>"); !reflect.DeepEqual(got, []string{"Empty"}) {
		t.Fatalf("a list of only Windows tokens should clear rather than fail, got %#v", got)
	}
}

// networksetup takes the host and the port as separate arguments.
func TestSplitEndpoint(t *testing.T) {
	host, port := splitEndpoint("127.0.0.1:2080")
	if host != "127.0.0.1" || port != "2080" {
		t.Fatalf("splitEndpoint = %q, %q", host, port)
	}
	if host, port := splitEndpoint("127.0.0.1"); host != "127.0.0.1" || port != "" {
		t.Fatalf("an address with no port should not invent one, got %q, %q", host, port)
	}
}

func TestProxyScriptBatchesAndQuotesEveryService(t *testing.T) {
	script := proxyScript([]string{"Wi-Fi O'Brien", "Ethernet"}, State{
		Enabled:  true,
		Override: "localhost;<local>",
	}, "127.0.0.1", "2080")

	if got := strings.Count(script, networksetup); got != 8 {
		t.Fatalf("expected four commands for each service, got %d: %s", got, script)
	}
	for _, want := range []string{
		"'-setwebproxy' 'Wi-Fi O'\"'\"'Brien' '127.0.0.1' '2080'",
		"'-setsecurewebproxy' 'Ethernet' '127.0.0.1' '2080'",
		"'-setproxybypassdomains' 'Ethernet' 'localhost'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected proxy script to contain %q, got: %s", want, script)
		}
	}
}

func TestVerifyServicesRejectsAnyUnconfiguredService(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080"}
	err := verifyServices([]string{"Ethernet", "Wi-Fi"}, want, func(service string) (State, error) {
		if service == "Wi-Fi" {
			return State{}, nil
		}
		return want, nil
	})
	if err == nil || !strings.Contains(err.Error(), "Wi-Fi") {
		t.Fatalf("expected the failed service to reject verification, got %v", err)
	}
}

func TestVerifyServicesAcceptsOnlyWhenEveryServiceMatches(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080"}
	if err := verifyServices([]string{"Ethernet", "Wi-Fi"}, want, func(string) (State, error) {
		return want, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := verifyServices([]string{"Wi-Fi"}, want, func(string) (State, error) {
		return State{}, errors.New("networksetup failed")
	}); err == nil {
		t.Fatal("read errors must fail verification")
	}
}

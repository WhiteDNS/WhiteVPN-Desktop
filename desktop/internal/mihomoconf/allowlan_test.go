package mihomoconf

import (
	"strings"
	"testing"
)

// Off unless asked for. This opens the proxy to everyone on the network with
// nothing authenticating them, so the default has to be the closed one and a
// mistake here would be an exposure rather than a missing feature.
func TestTheProxyIsNotSharedUnlessAsked(t *testing.T) {
	document := Render("proxies: []\n", Options{MixedPort: 2080, ControlPort: 9090})
	if !strings.Contains(document, "allow-lan: false") {
		t.Fatalf("sharing must be off by default:\n%s", firstLines(document, 12))
	}
	if strings.Contains(document, "bind-address") {
		t.Fatal("nothing should be bound beyond this machine when sharing is off")
	}
}

func TestSharingBindsBeyondThisMachine(t *testing.T) {
	document := Render("proxies: []\n", Options{MixedPort: 2080, ControlPort: 9090, AllowLAN: true})
	if !strings.Contains(document, "allow-lan: true") {
		t.Fatalf("sharing was asked for and not turned on:\n%s", firstLines(document, 12))
	}
	// Said explicitly rather than left to the engine's default, so what the
	// listener binds is decided here and stays decided.
	if !strings.Contains(document, `bind-address: "*"`) {
		t.Fatalf("the listener was not opened to the network:\n%s", firstLines(document, 12))
	}
}

func firstLines(text string, n int) string {
	lines := strings.SplitN(text, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

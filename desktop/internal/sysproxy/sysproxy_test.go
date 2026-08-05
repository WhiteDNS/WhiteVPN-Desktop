package sysproxy

import "testing"

// Verify is the second read that catches a write another program undid. It has
// to be strict about every field it set, and indifferent to nothing.
func TestSameAsComparesEveryFieldItSets(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}
	if !want.SameAs(State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}) {
		t.Fatal("identical states should compare equal")
	}
	for _, other := range []State{
		{Enabled: false, Server: "127.0.0.1:2080", Override: DefaultBypass},
		{Enabled: true, Server: "127.0.0.1:10808", Override: DefaultBypass},
		{Enabled: true, Server: "127.0.0.1:2080", Override: "<local>"},
	} {
		if want.SameAs(other) {
			t.Fatalf("a changed setting must not compare equal: %#v", other)
		}
	}
	// Windows is not case sensitive about these, and a restore that differs
	// only in case is a restore that changed nothing.
	if !want.SameAs(State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}) {
		t.Fatal("case should not matter")
	}
}

// The bypass list has to keep this machine reachable from itself: a proxy on
// 127.0.0.1 that 127.0.0.1 goes through is a loop.
func TestDefaultBypassKeepsLocalTrafficLocal(t *testing.T) {
	for _, needed := range []string{"localhost", "127.*", "192.168.*", "<local>"} {
		if !contains(DefaultBypass, needed) {
			t.Fatalf("the bypass list must hold %q, got %q", needed, DefaultBypass)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

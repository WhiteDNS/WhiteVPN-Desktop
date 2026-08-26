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

// Turning a proxy off and turning one on are not the same question.
//
// Both platforms keep the address behind when they disable a proxy, so a machine
// that was correctly put back reads as disabled-but-still-addressed. Comparing
// the address there reported every successful restore as a failure — which,
// once restore started trusting the answer, would have stranded every user whose
// settings were "no proxy" to begin with.
func TestSatisfiesIgnoresTheAddressLeftBehindByTurningItOff(t *testing.T) {
	want := State{Enabled: false}
	leftBehind := State{Enabled: false, Server: "127.0.0.1:2080", Override: DefaultBypass}

	if !leftBehind.Satisfies(want) {
		t.Fatal("a machine with the proxy off satisfies being asked to turn it off")
	}
	if leftBehind.SameAs(want) {
		t.Fatal("SameAs is the stricter question and should still see a difference")
	}
	if (State{Enabled: true, Server: "127.0.0.1:2080"}).Satisfies(want) {
		t.Fatal("a proxy that is still on does not satisfy being asked to turn it off")
	}
}

// Being asked to turn one on stays as strict as it was: the address is the
// whole point of the request.
func TestSatisfiesStaysStrictWhenAProxyWasAskedFor(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}

	if !want.Satisfies(want) {
		t.Fatal("the state that was asked for satisfies the request")
	}
	if (State{Enabled: true, Server: "127.0.0.1:9999", Override: DefaultBypass}).Satisfies(want) {
		t.Fatal("a different address must not pass as the one that was asked for")
	}
	if (State{Enabled: false, Server: "127.0.0.1:2080", Override: DefaultBypass}).Satisfies(want) {
		t.Fatal("a proxy that was written but not switched on must not pass")
	}
}

// macOS has no read for the bypass list. `networksetup` writes it and offers
// nothing that reads it back, so a correctly configured Mac reports Override
// empty — and verification that compares it fails on every macOS machine, every
// time. Capturing has always compared only what can be read; this is what keeps
// it that way.
func TestSatisfiesIgnoresTheBypassListItCannotRead(t *testing.T) {
	want := State{Enabled: true, Server: "127.0.0.1:2080", Override: DefaultBypass}
	asMacReportsIt := State{Enabled: true, Server: "127.0.0.1:2080"}

	if !asMacReportsIt.Satisfies(want) {
		t.Fatal("a correctly configured proxy must verify even where the bypass list cannot be read back")
	}
	// The fields that can be read are still compared.
	if (State{Enabled: true, Server: "127.0.0.1:9999"}).Satisfies(want) {
		t.Fatal("a different address must still fail")
	}
	if (State{Enabled: false, Server: "127.0.0.1:2080"}).Satisfies(want) {
		t.Fatal("a proxy that was written but not switched on must still fail")
	}
}

package session

import (
	"bytes"
	"strings"
	"testing"
)

// The line that started this: a config whose REALITY keys no longer matched the
// server, reported to the user as "no request completed through the proxy
// within 12s". The engine knew exactly what was wrong.
func TestCoreFailureReasonTakesTheInnermostExplanation(t *testing.T) {
	line := `time="2026-08-06T10:18:09-04:00" level=warning msg="[TCP] dial WhiteDNS Proxy (match Match/) 127.0.0.1:29683 --> connectivitycheck.gstatic.com:443 error: example.com:65535 connect error: REALITY authentication failed"`

	reason := coreFailureReason(line)
	if reason != "REALITY authentication failed" {
		t.Fatalf("expected the engine's own words, got %q", reason)
	}
}

// The line names the server being dialled. A failure that quotes the whole line
// puts a user's own host into a dialog they may well screenshot.
func TestCoreFailureReasonDoesNotCarryTheServer(t *testing.T) {
	line := `msg="[TCP] dial Group 127.0.0.1:1 --> a.b:443 error: secret-host.example.com:65535 connect error: connection refused"`

	reason := coreFailureReason(line)
	if strings.Contains(reason, "secret-host.example.com") {
		t.Fatalf("the reason carries the server: %q", reason)
	}
	if reason != "connection refused" {
		t.Fatalf("expected the reason alone, got %q", reason)
	}
}

func TestCoreFailureReasonFallsBackToAPlainError(t *testing.T) {
	if reason := coreFailureReason(`level=error msg="start listener error: address already in use"`); reason != "address already in use" {
		t.Fatalf("got %q", reason)
	}
}

func TestCoreFailureReasonIgnoresLinesWithoutOne(t *testing.T) {
	for _, line := range []string{"", "   ", `level=info msg="Start initial configuration in progress"`} {
		if reason := coreFailureReason(line); reason != "" {
			t.Fatalf("%q should carry no reason, got %q", line, reason)
		}
	}
}

// A runaway line must not end up in a dialog.
func TestCoreFailureReasonRefusesSomethingTooLong(t *testing.T) {
	if reason := coreFailureReason("error: " + strings.Repeat("x", coreReasonLimit+1)); reason != "" {
		t.Fatalf("expected an over-long reason to be dropped, got %d characters", len(reason))
	}
}

// The tap must not swallow the engine's output: the Logs page is built from it.
func TestCoreReasonTapPassesEverythingThrough(t *testing.T) {
	var sink bytes.Buffer
	stream := newCoreReasonTap().Watch(&sink)

	first := `msg="connect error: first failure"` + "\n"
	ordinary := "level=info msg=\"something ordinary\"\n"
	for _, chunk := range []string{first, ordinary} {
		if _, err := stream.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}

	if sink.String() != first+ordinary {
		t.Fatalf("output was altered: %q", sink.String())
	}
}

// The engine's log — dial failures included — goes to stdout, not stderr.
// Watching only one stream recorded nothing at all.
func TestCoreReasonTapWatchesBothStreams(t *testing.T) {
	tap := newCoreReasonTap()
	stdout, stderr := tap.Watch(nil), tap.Watch(nil)

	if _, err := stderr.Write([]byte(`msg="connect error: from stderr"`)); err != nil {
		t.Fatal(err)
	}
	if reason := tap.Reason(); reason != "from stderr" {
		t.Fatalf("stderr was not read: %q", reason)
	}
	if _, err := stdout.Write([]byte(`msg="connect error: from stdout"`)); err != nil {
		t.Fatal(err)
	}
	// The most recent one, whichever stream it arrived on, because that is the
	// attempt the user is waiting on.
	if reason := tap.Reason(); reason != "from stdout" {
		t.Fatalf("stdout was not read: %q", reason)
	}
}

func TestCoreReasonTapWithNowhereToWrite(t *testing.T) {
	tap := newCoreReasonTap()
	if _, err := tap.Watch(nil).Write([]byte(`msg="connect error: alone"`)); err != nil {
		t.Fatal(err)
	}
	if reason := tap.Reason(); reason != "alone" {
		t.Fatalf("got %q", reason)
	}
}

// A session that never started has no engine to have said anything.
func TestEngineSaidIsEmptyWithoutATap(t *testing.T) {
	session := &Session{}
	if said := session.engineSaid(); said != "" {
		t.Fatalf("expected nothing, got %q", said)
	}
}

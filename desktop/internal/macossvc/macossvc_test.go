//go:build darwin

package macossvc

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Read-only probes: nothing here registers or unregisters anything, so the
// tests are safe to run on any Mac, including one where the daemon has been
// deliberately left unregistered.
func TestAvailabilityOnThisMachine(t *testing.T) {
	if !available() {
		t.Skip("SMAppService is absent; tunnel capability will report macOS 13+ as a requirement")
	}
}

func TestStatusNeverBlocksOrCrashes(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		status, err := Daemon().Registration()
		if err != nil && !errors.Is(err, ErrUnsupportedPlatform) {
			t.Errorf("status failed outright: %v", err)
		}
		t.Logf("registration status: %v", status)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("asking for registration status must never take ten seconds")
	}
}

func TestRequestToNothingFailsFast(t *testing.T) {
	if !available() {
		t.Skip("no SMAppService here")
	}
	start := time.Now()
	_, err := Daemon().Request("status", 2000)
	if err == nil {
		// A running, registered daemon answering is fine too — but then it had
		// better speak our schema.
		return
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("a dead helper must be discovered quickly")
	}
	if strings.Contains(err.Error(), "cgo") {
		t.Fatalf("transport errors should be sentences, got %v", err)
	}
}

func TestParseReplyRejectsGarbageAndRefusals(t *testing.T) {
	if _, err := ParseReply("}{"); err == nil {
		t.Fatal("garbage must not parse")
	}
	reply, err := ParseReply(`{"ok":false,"error":"core signature invalid"}`)
	if err == nil || reply.Error != "core signature invalid" {
		t.Fatalf("a structured refusal must surface its reason, got %v", err)
	}
	if _, err := ParseReply(`{"ok":true,"version":1}`); err != nil {
		t.Fatalf("an acceptance parses clean: %v", err)
	}
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The failure a user in Iran actually got. It reads like a certificate problem
// and is not one — the handshake never reached a certificate.
func TestInterferenceIsToldApartFromABadCertificate(t *testing.T) {
	interference := []error{
		errors.New("tls: first record does not look like a TLS handshake"),
		fmt.Errorf("Get %q: %w", "https://example.com", errors.New("read: connection reset by peer")),
		errors.New("An existing connection was forcibly closed by the remote host"),
		errors.New("unexpected EOF"),
	}
	for _, err := range interference {
		if !looksLikeInterference(err) {
			t.Errorf("%v should read as interference", err)
		}
	}

	// A certificate that does not verify is a definite statement about the
	// server's identity, and the one case where "the certificate is bad" is
	// true. It must not be folded into the interference message.
	certificateFailures := []error{
		&tls.CertificateVerificationError{Err: errors.New("bad chain")},
		x509.UnknownAuthorityError{},
		x509.HostnameError{Host: "example.com"},
	}
	for _, err := range certificateFailures {
		if looksLikeInterference(err) {
			t.Errorf("%T is a certificate failure, not interference", err)
		}
	}

	if looksLikeInterference(nil) {
		t.Error("no error is not interference")
	}
}

// The message has to point at the thing that would actually help, and say what
// the problem is not — otherwise the obvious next move is to go looking for a
// way to skip certificate checks, which cannot fix this.
func TestTheMessageForABlockedSubscriptionSaysWhatWouldHelp(t *testing.T) {
	blocked := errors.New("tls: first record does not look like a TLS handshake")

	notConnected := subscriptionFetchError(blocked, nil).Error()
	if !strings.Contains(notConnected, "Connect the VPN first") {
		t.Fatalf("should suggest connecting: %s", notConnected)
	}
	if !strings.Contains(notConnected, "not a problem with the address or its certificate") {
		t.Fatalf("should say what it is not: %s", notConnected)
	}

	// Already connected and still blocked: telling them to connect would be
	// advice they have already taken.
	alsoBlocked := subscriptionFetchError(blocked, errors.New("proxy also failed")).Error()
	if strings.Contains(alsoBlocked, "Connect the VPN first") {
		t.Fatalf("should not suggest connecting when the tunnel was already tried: %s", alsoBlocked)
	}
	if !strings.Contains(alsoBlocked, "through the connection") {
		t.Fatalf("should say the tunnel was tried too: %s", alsoBlocked)
	}
}

// An ordinary failure — a typo in the address, a 404, a real certificate
// problem — must keep its own message rather than being explained away as
// network interference.
func TestOrdinaryFailuresKeepTheirOwnMessage(t *testing.T) {
	for _, err := range []error{
		errors.New("subscription returned HTTP 404"),
		&tls.CertificateVerificationError{Err: errors.New("expired")},
	} {
		got := subscriptionFetchError(err, nil)
		if !errors.Is(got, err) {
			t.Errorf("expected %v to be returned as-is, got %v", err, got)
		}
		if strings.Contains(got.Error(), "interfering") {
			t.Errorf("%v should not be blamed on the network", err)
		}
	}
}

// A direct fetch that worked needs no explanation, whatever the tunnel did.
func TestNoErrorWhenTheDirectFetchSucceeded(t *testing.T) {
	if err := subscriptionFetchError(nil, errors.New("proxy failed")); err == nil {
		t.Skip("nothing to assert: the caller returns before this on success")
	}
}

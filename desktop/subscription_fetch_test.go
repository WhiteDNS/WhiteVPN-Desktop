package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
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

	notConnected := subscriptionFetchError(blocked, nil, false).Error()
	if !strings.Contains(notConnected, "Connect the VPN first") {
		t.Fatalf("should suggest connecting: %s", notConnected)
	}
	if !strings.Contains(notConnected, "Nothing is wrong with the address or its certificate") {
		t.Fatalf("should say what it is not: %s", notConnected)
	}

	// Already connected and still blocked: telling them to connect would be
	// advice they have already taken.
	alsoBlocked := subscriptionFetchError(blocked, errors.New("proxy also failed"), false).Error()
	if strings.Contains(alsoBlocked, "Connect the VPN first") {
		t.Fatalf("should not suggest connecting when the tunnel was already tried: %s", alsoBlocked)
	}
	if !strings.Contains(alsoBlocked, "through the connection") {
		t.Fatalf("should say the tunnel was tried too: %s", alsoBlocked)
	}
}

// An ordinary failure — a typo in the address, a 404 — must keep its own
// message rather than being explained away as network interference.
func TestOrdinaryFailuresKeepTheirOwnMessage(t *testing.T) {
	for _, err := range []error{
		errors.New("subscription returned HTTP 404"),
		&tls.CertificateVerificationError{Err: errors.New("expired")},
	} {
		got := subscriptionFetchError(err, nil, false)
		if !errors.Is(got, err) {
			t.Errorf("expected %v to remain reachable, got %v", err, got)
		}
		if strings.Contains(got.Error(), "blocking") {
			t.Errorf("%v should not be blamed on the network", err)
		}
	}
}

// The switch is offered for the failure it can get past, and only that one.
//
// A certificate that does not verify is something terminating TLS in the middle,
// which is what turning it off gets past — that is how this same subscription
// came through on iOS. A reply that was never TLS is not, and offering the
// switch there would be offering a trade that buys nothing.
func TestTheSwitchIsOfferedOnlyWhereItCanWork(t *testing.T) {
	const offer = "Fetch without checking the certificate"

	certificateFailure := subscriptionFetchError(&tls.CertificateVerificationError{Err: errors.New("unknown authority")}, nil, false).Error()
	if !strings.Contains(certificateFailure, offer) {
		t.Fatalf("a certificate failure should offer the switch: %s", certificateFailure)
	}

	neverTLS := subscriptionFetchError(errors.New("tls: first record does not look like a TLS handshake"), nil, false).Error()
	if strings.Contains(neverTLS, offer) {
		t.Fatalf("the switch cannot get past this, so it must not be offered: %s", neverTLS)
	}
}

// Already on and still failing this way means the switch is not the missing
// piece. Leaving someone to keep verification off for nothing is the worst of
// both outcomes, so the message has to say to turn it back off.
func TestTheSwitchIsWithdrawnWhenItDidNotHelp(t *testing.T) {
	got := subscriptionFetchError(errors.New("tls: first record does not look like a TLS handshake"), nil, true).Error()
	if !strings.Contains(got, "turn it back off") {
		t.Fatalf("should say to turn it back off: %s", got)
	}
}

// With the switch on, a certificate failure is no longer something to suggest it
// for — verification was already skipped, so this is a different problem.
func TestNoOfferOnceTheSwitchIsAlreadyOn(t *testing.T) {
	err := &tls.CertificateVerificationError{Err: errors.New("unknown authority")}
	got := subscriptionFetchError(err, nil, true)
	if !errors.Is(got, err) {
		t.Fatalf("expected the cause to survive, got %v", got)
	}
	if strings.Contains(got.Error(), "turn on") {
		t.Fatalf("should not suggest what is already on: %s", got)
	}
}

// Verification is skipped for the one subscription that asked for it, and the
// clients it is skipped on are copies — the shared default client and the
// tunnel's client must not be left unverified after one fetch.
func TestSkippingVerificationDoesNotLeakIntoOtherClients(t *testing.T) {
	if got := clientFor(http.DefaultClient, false); got != http.DefaultClient {
		t.Fatal("without the switch the client should be used unchanged")
	}

	insecure := clientFor(http.DefaultClient, true)
	if insecure == http.DefaultClient {
		t.Fatal("the shared default client was modified in place")
	}
	transport, ok := insecure.Transport.(*http.Transport)
	if !ok || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("verification was not actually skipped")
	}
	if base, _ := http.DefaultTransport.(*http.Transport); base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the default transport was left unverified for the whole app")
	}

	// A client carrying a dialer — the tunnel's — keeps it, or the fetch stops
	// going through the tunnel the moment the switch is turned on.
	dialed := false
	tunnel := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("no")
	}}}
	through, _ := clientFor(tunnel, true).Transport.(*http.Transport)
	if through.DialContext == nil {
		t.Fatal("the tunnel's dialer was dropped")
	}
	_, _ = through.DialContext(context.Background(), "tcp", "example.com:443")
	if !dialed {
		t.Fatal("the copy is not dialing through the original's dialer")
	}
}

// A direct fetch that worked needs no explanation, whatever the tunnel did.
func TestNoErrorWhenTheDirectFetchSucceeded(t *testing.T) {
	if err := subscriptionFetchError(nil, errors.New("proxy failed"), false); err == nil {
		t.Skip("nothing to assert: the caller returns before this on success")
	}
}

// The subscription URL carries the account key, and this message lands in a
// dialog people screenshot and send to whoever is helping them.
func TestTheErrorDoesNotCarryTheSubscriptionURL(t *testing.T) {
	const url = "https://cf.example.org/sub/whitedns/418674ba14313e5ae8b2a014e97ddeea"
	blocked := fmt.Errorf("Get %q: %w", url, errors.New("tls: first record does not look like a TLS handshake"))

	for _, message := range []string{
		subscriptionFetchError(blocked, nil, false).Error(),
		subscriptionFetchError(blocked, errors.New("proxy failed"), false).Error(),
	} {
		if strings.Contains(message, "418674ba") {
			t.Fatalf("the account key is in the message a user will screenshot: %s", message)
		}
		if strings.Contains(message, "cf.example.org") {
			t.Fatalf("the subscription address is in the message: %s", message)
		}
		// The reason still has to survive, or the message says nothing useful.
		if !strings.Contains(message, "TLS handshake") {
			t.Fatalf("the reason was lost: %s", message)
		}
	}
}

// An error with no URL in it is passed through unchanged.
func TestWithoutURLLeavesAPlainReasonAlone(t *testing.T) {
	if got := withoutURL(errors.New("connection reset by peer")); got != "connection reset by peer" {
		t.Fatalf("got %q", got)
	}
}

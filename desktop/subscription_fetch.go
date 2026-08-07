package main

// Fetching a subscription from a network that does not want you to.
//
// A user in Iran could not add a subscription: the app reported
//
//	tls: first record does not look like a TLS handshake
//
// and another client on the same machine offered a "fetch without checking the
// certificate" switch, so the obvious reading was that the certificate was bad.
// It is not. Fetched from elsewhere the same address answers with a valid
// certificate and the right content; the error means the bytes coming back are
// not TLS at all, which is what interference on the path looks like. Skipping
// certificate verification cannot help, because verification is not what failed
// — the handshake never got that far. A switch for it would be turned on, would
// change nothing, and would leave someone believing they had traded away a
// protection to fix a problem it had nothing to do with. The subscription URL
// carries the account key, so that trade is not free.
//
// What does help is the tunnel. If the app is connected, it already has a path
// out of that network, and the subscription can be fetched through it — the same
// answer the update check uses, for the same reason.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// fetchSubscriptionDocument fetches a subscription, through the running tunnel
// when there is one.
//
// Both paths are tried rather than one chosen. Connected does not guarantee the
// tunnel reaches everything, and not connected does not mean a direct fetch will
// fail — so whichever answers first is the answer.
func (a *App) fetchSubscriptionDocument(ctx context.Context, rawURL string) (string, error) {
	var directErr, proxiedErr error

	if proxied, err := a.proxyHTTPClient(); err == nil && proxied != nil {
		body, err := fetchV2RaySubscriptionDocumentWith(ctx, rawURL, proxied)
		if err == nil {
			return body, nil
		}
		proxiedErr = err
	}

	body, err := fetchV2RaySubscriptionDocumentWith(ctx, rawURL, http.DefaultClient)
	if err == nil {
		return body, nil
	}
	directErr = err

	return "", subscriptionFetchError(directErr, proxiedErr)
}

// subscriptionFetchError says what actually went wrong, and what would help.
//
// The error a user sees for a blocked address is otherwise a sentence about TLS
// records that reads like a fault in their subscription, and the thing it most
// resembles — a bad certificate — is the one thing it is not.
func subscriptionFetchError(directErr, proxiedErr error) error {
	if directErr == nil {
		return proxiedErr
	}
	if !looksLikeInterference(directErr) {
		return directErr
	}
	if proxiedErr != nil {
		// Both ways failed on a network that is interfering. The tunnel was
		// tried and did not get through either, which is worth saying so nobody
		// connects and tries again expecting a different outcome.
		return fmt.Errorf("could not reach the subscription, directly or through the connection — something on this network is interfering with it, not with the address itself: %w", directErr)
	}
	return fmt.Errorf("could not reach the subscription: something on this network is interfering with the connection to it. Connect the VPN first and try again — this is not a problem with the address or its certificate: %w", directErr)
}

// looksLikeInterference reports whether a failure has the shape of something on
// the path meddling, rather than the far end being at fault.
//
// A certificate that does not verify is deliberately *not* included. That is a
// definite statement about the server's identity and deserves its own message,
// and it is the one case where "the certificate is bad" is the truth.
func looksLikeInterference(err error) bool {
	if err == nil {
		return false
	}
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &verification) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) {
		return false
	}

	// What a middlebox leaves behind: a reply that is not TLS, a connection cut
	// mid-handshake, or one closed the moment it opened.
	text := strings.ToLower(err.Error())
	for _, marker := range []string{
		"first record does not look like a tls handshake",
		"connection reset by peer",
		"an existing connection was forcibly closed",
		"unexpected eof",
		"eof",
		"handshake failure",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

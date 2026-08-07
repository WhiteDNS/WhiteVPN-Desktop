package main

// Fetching a subscription from a network that does not want you to.
//
// Networks that filter do not all fail the same way, and the difference decides
// what can fix it. Two failures were seen on the same subscription:
//
//	tls: first record does not look like a TLS handshake
//
// means the bytes coming back are not TLS at all — something answered in place
// of the server. Verification never runs, so skipping it changes nothing. What
// helps there is the tunnel: once connected the app already has a path out of
// that network, and the subscription can be fetched through it.
//
// A certificate that does not verify is the other failure, and it is the
// opposite case. Something is terminating TLS and presenting its own
// certificate. Skipping verification does get the document — the same
// subscription that failed this way on iOS came through the moment that app's
// "fetch without checking the certificate" switch was turned on.
//
// So both exist here, and neither is offered where it cannot work. The switch is
// off by default and per-subscription: turning it on hands the account key in
// the URL to whoever is intercepting, which is a real cost and only the person
// who knows the provider and the network can weigh it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"strings"
	"whitevpn-desktop/internal/model"
)

// fetchSubscriptionDocument fetches a subscription, through the running tunnel
// when there is one.
//
// Both paths are tried rather than one chosen. Connected does not guarantee the
// tunnel reaches everything, and not connected does not mean a direct fetch will
// fail — so whichever answers first is the answer.
func (a *App) fetchSubscriptionDocument(ctx context.Context, subscription model.V2RaySubscription) (string, error) {
	var directErr, proxiedErr error
	skipVerify := subscription.AllowInsecureTLS

	if proxied, err := a.proxyHTTPClient(); err == nil && proxied != nil {
		body, err := fetchV2RaySubscriptionDocumentWith(ctx, subscription.URL, clientFor(proxied, skipVerify))
		if err == nil {
			return body, nil
		}
		proxiedErr = err
	}

	body, err := fetchV2RaySubscriptionDocumentWith(ctx, subscription.URL, clientFor(http.DefaultClient, skipVerify))
	if err == nil {
		return body, nil
	}
	directErr = err

	// The reply was not TLS, which is what a filter reading the ClientHello
	// leaves behind. Splitting that first write across segments too small to
	// hold the hostname gives it nothing to match on. Only on this failure: a
	// 404 or a bad certificate is not something a differently-shaped handshake
	// is going to fix, and retrying either would just be a second wait.
	if looksLikeInterference(directErr) {
		if fragmented := fragmentedDirectClient(skipVerify); fragmented != nil {
			if body, err := fetchV2RaySubscriptionDocumentWith(ctx, subscription.URL, fragmented); err == nil {
				return body, nil
			}
		}
	}

	return "", subscriptionFetchError(directErr, proxiedErr, skipVerify)
}

// clientFor returns base, or a copy of it that does not verify certificates.
//
// A copy, because base may be the shared default client or the one built for the
// running tunnel, and neither may be left with verification disabled after this
// one fetch.
func clientFor(base *http.Client, skipVerify bool) *http.Client {
	if !skipVerify {
		return base
	}
	source, ok := base.Transport.(*http.Transport)
	if !ok || source == nil {
		source, _ = http.DefaultTransport.(*http.Transport)
	}
	if source == nil {
		return base
	}
	transport := source.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true

	client := *base
	client.Transport = transport
	return &client
}

// subscriptionFetchError says what actually went wrong, and what would help.
//
// The error a user sees for a blocked address is otherwise a sentence about TLS
// records that reads like a fault in their subscription, and the thing it most
// resembles — a bad certificate — is the one thing it is not.
func subscriptionFetchError(directErr, proxiedErr error, skipVerify bool) error {
	if directErr == nil {
		return proxiedErr
	}
	// A certificate that does not verify is the one failure the switch answers,
	// so it is the one failure allowed to mention it.
	if looksLikeCertificateFailure(directErr) && !skipVerify {
		return explain(directErr, "this server's certificate could not be verified, so there is no proof this is the real address. If you trust this provider and this network, turn on \"Fetch without checking the certificate\" and try again.")
	}
	if !looksLikeInterference(directErr) {
		return directErr
	}
	// Turned on and still failing this way: the switch is not the missing piece
	// and leaving someone to keep it on for nothing is the worst outcome.
	if skipVerify {
		return explain(directErr, "something on this network is answering in place of this subscription's server, so nothing is getting through. \"Fetch without checking the certificate\" cannot help with this one — turn it back off. Connect the VPN first and refresh instead.")
	}
	if proxiedErr != nil {
		// Both ways failed on a network that is interfering. The tunnel was
		// tried and did not get through either, which is worth saying so nobody
		// connects and tries again expecting a different outcome.
		return explain(directErr, "Tried through the connection and it still could not be reached — something on the network is blocking this subscription, not the address itself.")
	}
	// The instruction leads. What this is not comes after it, because the
	// obvious next move otherwise is to go hunting for a way to skip the
	// certificate check, which cannot fix it.
	return explain(directErr, "Connect the VPN first, then refresh this subscription — something on this network is blocking it. Nothing is wrong with the address or its certificate.")
}

// explain carries the cause without printing it.
//
// fmt.Errorf with %w would put the cause's own text — including the subscription
// URL, and so the account key in it — into a message that ends up in a
// screenshot. Keeping the cause reachable by errors.Is and errors.As while the
// text stays ours means no future message can leak it by accident either.
type explainedError struct {
	message string
	reason  string
	cause   error
}

func (e *explainedError) Error() string { return fmt.Sprintf("%s (%s)", e.message, e.reason) }
func (e *explainedError) Unwrap() error { return e.cause }

func explain(cause error, message string) error {
	return &explainedError{message: message, reason: withoutURL(cause), cause: cause}
}

// withoutURL keeps the reason and drops the address it was reaching for.
//
// Go writes these as `Get "https://…": reason`, and that address is the
// subscription URL, which carries the user's account key. This message lands in
// a dialog people screenshot and send to whoever is helping them — it had
// already reached me twice that way before I noticed I was the one putting it
// there, having written a comment two files up about exactly this risk.
func withoutURL(err error) string {
	text := err.Error()
	if _, reason, found := strings.Cut(text, `": `); found {
		return strings.TrimSpace(reason)
	}
	return text
}

// looksLikeCertificateFailure reports whether the handshake got far enough to be
// shown a certificate and refused it.
//
// This is the failure the switch can get past, and telling it apart from a reply
// that was never TLS is the whole point — offering the switch for the other one
// would be offering a trade that buys nothing.
func looksLikeCertificateFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	return errors.As(err, &verification) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname)
}

// looksLikeInterference reports whether a failure has the shape of something on
// the path meddling, rather than the far end being at fault.
//
// A certificate that does not verify is deliberately *not* included. That is a
// definite statement about the server's identity and deserves its own message,
// and it is the one case where "the certificate is bad" is the truth.
func looksLikeInterference(err error) bool {
	if err == nil || looksLikeCertificateFailure(err) {
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

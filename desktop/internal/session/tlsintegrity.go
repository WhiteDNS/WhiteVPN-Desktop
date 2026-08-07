package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Checking that nobody is opening the TLS on the way through.
//
// A tunnel can carry traffic perfectly and still not be private: if whatever is
// between this machine and the internet is terminating TLS and re-issuing
// certificates, every page loads, the health check passes, the dashboard is
// green, and the connection is being read. The certificate is the only thing
// that says so.
//
// The ordinary health probe cannot tell. It verifies certificates — Go's default
// transport does — but it treats every error the same and moves to the next URL,
// so an intercepted connection is indistinguishable from a blocked one. This
// looks at *why* a request failed.
//
// It fails closed on a certificate failure and open on anything else, which is
// the same line Android draws ("all probes unreachable; allowing connection").
// The asymmetry is deliberate: a rejected certificate is evidence, while
// unreachable is the normal condition of the networks this app runs on, and
// refusing to connect every time three URLs are blocked would make the setting
// unusable exactly where it matters.
const (
	tlsIntegrityProbeTimeout = 2 * time.Second
	tlsIntegrityBudget       = 7 * time.Second
)

// ErrTLSIntercepted means a certificate did not verify through the tunnel.
var ErrTLSIntercepted = errors.New("session: TLS is being intercepted on this connection — certificates do not verify")

// verifyTLSIntegrity returns ErrTLSIntercepted when traffic through the proxy
// meets a certificate that does not check out.
func verifyTLSIntegrity(ctx context.Context, proxyPort int) error {
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	if err != nil {
		return nil
	}
	deadline, cancel := context.WithTimeout(ctx, tlsIntegrityBudget)
	defer cancel()

	client := &http.Client{
		Timeout: tlsIntegrityProbeTimeout,
		// No TLSClientConfig, so Go verifies the chain and the host name. That
		// verification is the whole check; skipping it here — as a health probe
		// might reasonably do — would make this function a no-op that looks like
		// a security feature.
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, target := range healthURLs {
		if deadline.Err() != nil {
			break
		}
		request, err := http.NewRequestWithContext(deadline, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			// One verified handshake is enough. If TLS were being opened, this
			// is where it would have failed.
			return nil
		}
		if isCertificateFailure(err) {
			return fmt.Errorf("%w (%s)", ErrTLSIntercepted, hostOf(target))
		}
	}

	// Nothing answered. That says nothing about interception, so it must not be
	// read as evidence of it.
	return nil
}

// isCertificateFailure reports whether an error is TLS refusing a certificate,
// as opposed to the request never getting that far.
//
// The distinction is the entire point: connection refused, a timeout and a
// blocked address are all ordinary here, and treating them as interception would
// make the setting refuse to connect on any censored network.
func isCertificateFailure(err error) bool {
	if err == nil {
		return false
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid)
}

func hostOf(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	return parsed.Host
}

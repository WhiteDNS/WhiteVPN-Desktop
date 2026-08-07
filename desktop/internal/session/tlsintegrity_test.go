package session

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
)

// The whole check turns on this distinction. A rejected certificate is evidence
// of interception; connection refused is the normal condition of the networks
// this app runs on, and treating the two alike would either miss the attack or
// refuse to connect anywhere.
func TestCertificateFailuresAreToldApartFromUnreachable(t *testing.T) {
	certificateFailures := []error{
		&tls.CertificateVerificationError{Err: errors.New("bad chain")},
		x509.UnknownAuthorityError{},
		x509.HostnameError{Host: "example.com"},
		x509.CertificateInvalidError{Reason: x509.Expired},
		// Wrapped, because that is how they arrive out of net/http.
		fmt.Errorf("Get %q: %w", "https://example.com",
			&tls.CertificateVerificationError{Err: errors.New("bad chain")}),
	}
	for _, err := range certificateFailures {
		if !isCertificateFailure(err) {
			t.Errorf("%T should count as a certificate failure", err)
		}
	}

	ordinary := []error{
		nil,
		errors.New("connection refused"),
		&net.OpError{Op: "dial", Err: errors.New("network is unreachable")},
		context_DeadlineExceeded(),
		fmt.Errorf("Get %q: %w", "https://example.com", errors.New("EOF")),
	}
	for _, err := range ordinary {
		if isCertificateFailure(err) {
			t.Errorf("%v should not count as a certificate failure", err)
		}
	}
}

func context_DeadlineExceeded() error {
	return errors.New("context deadline exceeded")
}

func TestHostOfNamesTheServerInTheFailure(t *testing.T) {
	if host := hostOf("https://cloudflare.com/cdn-cgi/trace"); host != "cloudflare.com" {
		t.Fatalf("got %q", host)
	}
	// Something unparseable is reported as-is rather than swallowed.
	if host := hostOf("::nonsense"); host == "" {
		t.Fatal("an unparseable target should still be named")
	}
}

// Nothing answering says nothing about interception. Reading it as evidence
// would make the setting refuse to connect on any censored network, which is
// where it is most needed.
func TestUnreachableProbesDoNotReportInterception(t *testing.T) {
	// Nothing is listening on this port, so every probe fails to connect.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	if err := verifyTLSIntegrity(t.Context(), port); err != nil {
		t.Fatalf("an unreachable proxy should not be reported as interception: %v", err)
	}
}

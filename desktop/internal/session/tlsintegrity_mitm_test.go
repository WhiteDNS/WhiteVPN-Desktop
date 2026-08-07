package session

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// The case the setting exists for, stood up for real.
//
// A proxy that terminates TLS and re-issues certificates from an authority
// nobody trusts is exactly what interception looks like from inside the tunnel:
// every request completes, the health check passes, the dashboard goes green,
// and the connection is being read. The only thing that says so is the
// certificate — so this builds one and checks that the connection is refused.
func TestInterceptedTLSIsRefused(t *testing.T) {
	intercepting := startInterceptingProxy(t)

	err := verifyTLSIntegrity(t.Context(), intercepting)
	if err == nil {
		t.Fatal("an intercepted connection was accepted")
	}
	if !errors.Is(err, ErrTLSIntercepted) {
		t.Fatalf("expected interception to be named, got %v", err)
	}
	t.Logf("refused, as it should be: %v", err)
}

// startInterceptingProxy runs an HTTP proxy that answers CONNECT itself and
// presents a certificate from an authority the machine does not trust, then
// returns the port it listens on.
func startInterceptingProxy(t *testing.T) int {
	t.Helper()

	authority, authorityKey := selfSignedAuthority(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go interceptOne(client, authority, authorityKey)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func interceptOne(client net.Conn, authority *x509.Certificate, authorityKey *ecdsa.PrivateKey) {
	defer client.Close()

	request, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	host, _, err := net.SplitHostPort(request.Host)
	if err != nil {
		host = request.Host
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// From here the proxy is the TLS server, which is the interception.
	leaf, leafKey := issueFor(host, authority, authorityKey)
	if leaf == nil {
		return
	}
	server := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Raw, authority.Raw},
			PrivateKey:  leafKey,
		}},
	})
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	// The handshake is where the client rejects us; nothing after it matters.
	_ = server.Handshake()
	_ = server.Close()
}

func selfSignedAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Not A Real Authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func issueFor(host string, authority *x509.Certificate, authorityKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority, &key.PublicKey, authorityKey)
	if err != nil {
		return nil, nil
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil
	}
	return certificate, key
}

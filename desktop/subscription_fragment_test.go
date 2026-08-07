package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
)

// recordingConn keeps every write separately, which is the whole point: what
// matters is not what was sent but how many pieces it arrived in.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingConn) pieces() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// clientHello is a plausible opening record: a handshake record whose body
// starts with client_hello and carries a hostname in the clear.
func clientHello(hostname string) []byte {
	body := append([]byte{0x01, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x2a}, 200)...)
	body = append(body, []byte(hostname)...)
	body = append(body, bytes.Repeat([]byte{0x2a}, 200)...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
}

// A hostname arriving in one segment is all a filter needs. Many pieces is the
// property being bought here, so it is the one asserted.
func TestTheClientHelloIsSplitIntoManyPieces(t *testing.T) {
	recorder := &recordingConn{}
	conn := &fragmentingConn{Conn: recorder}

	hello := clientHello("cf.example.org")
	n, err := conn.Write(hello)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(hello) {
		t.Fatalf("reported %d bytes written of %d", n, len(hello))
	}

	pieces := recorder.pieces()
	if len(pieces) < 32 {
		t.Fatalf("a handshake split into %d pieces is still one a filter can read", len(pieces))
	}
	if got := bytes.Join(pieces, nil); !bytes.Equal(got, hello) {
		t.Fatal("the server would not reassemble the handshake that was sent")
	}
}

// The point is not that it is split, but that no piece is big enough to hold
// what a filter is looking for.
func TestNoPieceCanHoldTheHostname(t *testing.T) {
	const hostname = "cf.example.org"
	recorder := &recordingConn{}
	conn := &fragmentingConn{Conn: recorder}
	if _, err := conn.Write(clientHello(hostname)); err != nil {
		t.Fatal(err)
	}

	for i, piece := range recorder.pieces() {
		if len(piece) > maxFragmentSize {
			t.Fatalf("piece %d is %d bytes, over the %d-byte limit", i, len(piece), maxFragmentSize)
		}
		if bytes.Contains(piece, []byte(hostname)) {
			t.Fatalf("piece %d carries the hostname whole", i)
		}
	}
	// Even the largest piece must be too short for the shortest name worth
	// filtering, or the limit above is set wrong.
	if maxFragmentSize >= len(hostname) {
		t.Fatalf("a %d-byte piece can hold %q", maxFragmentSize, hostname)
	}
}

// Everything after the handshake is encrypted and carries nothing to match on.
// Splitting it would slow every byte of the response for no gain.
func TestOnlyTheHandshakeIsSplit(t *testing.T) {
	recorder := &recordingConn{}
	conn := &fragmentingConn{Conn: recorder}

	if _, err := conn.Write(clientHello("cf.example.org")); err != nil {
		t.Fatal(err)
	}
	fragmented := len(recorder.pieces())

	// Application data, after the handshake.
	body := append([]byte{0x17, 0x03, 0x03, 0x01, 0x00}, bytes.Repeat([]byte{0x7e}, 256)...)
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	if got := len(recorder.pieces()) - fragmented; got != 1 {
		t.Fatalf("everything after the handshake should go out whole, went out in %d pieces", got)
	}
}

// A connection that never sends a ClientHello — plain HTTP — must be left alone
// entirely.
func TestPlainHTTPIsUntouched(t *testing.T) {
	recorder := &recordingConn{}
	conn := &fragmentingConn{Conn: recorder}

	request := []byte("GET /sub HTTP/1.1\r\nHost: cf.example.org\r\n\r\n")
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	pieces := recorder.pieces()
	if len(pieces) != 1 || !bytes.Equal(pieces[0], request) {
		t.Fatalf("a plain request should go out in one piece, got %d", len(pieces))
	}
}

// Fragmenting changes how the handshake is packetised and nothing else. It must
// not quietly become a way to accept any certificate.
func TestCertificatesAreStillVerified(t *testing.T) {
	client := fragmentedDirectClient(false)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected an *http.Transport")
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("fragmenting must not disable certificate verification")
	}

	// And when the subscription did ask for it, that choice still carries.
	insecure := fragmentedDirectClient(true)
	insecureTransport, _ := insecure.Transport.(*http.Transport)
	if !insecureTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the subscription's own setting was dropped")
	}
}

// The default transport is the whole process's. Giving every request a
// fragmenting dialer to fix one fetch would be a cost paid forever.
func TestTheDefaultTransportIsNotMutated(t *testing.T) {
	base, _ := http.DefaultTransport.(*http.Transport)
	before := base.DialContext

	_ = fragmentedDirectClient(false)
	_ = fragmentedDirectClient(true)

	if base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the whole app was left skipping certificate verification")
	}
	if (before == nil) != (base.DialContext == nil) {
		t.Fatal("the default transport's dialer was replaced")
	}
}

// A millisecond between pieces of a handshake is nothing; a millisecond between
// pieces of something large would be minutes. The guard is that only the
// handshake is ever split, and this puts a number on it.
func TestFragmentingStaysFast(t *testing.T) {
	recorder := &recordingConn{}
	conn := &fragmentingConn{Conn: recorder}

	start := time.Now()
	if _, err := conn.Write(clientHello("cf.example.org")); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("splitting one handshake took %s", elapsed)
	}
}

func TestAClientHelloIsRecognisedByItsHeader(t *testing.T) {
	hello := clientHello("cf.example.org")
	if !looksLikeTLSClientHello(hello) {
		t.Fatal("a real ClientHello was not recognised")
	}

	for name, payload := range map[string][]byte{
		"empty":               {},
		"too short":           {0x16, 0x03, 0x01, 0x00},
		"application data":    {0x17, 0x03, 0x03, 0x00, 0x10, 0x01},
		"alert":               {0x15, 0x03, 0x03, 0x00, 0x02, 0x01},
		"wrong major version": {0x16, 0x02, 0x00, 0x00, 0x10, 0x01},
		"server hello":        {0x16, 0x03, 0x01, 0x00, 0x10, 0x02},
		"plain HTTP":          []byte("GET / HTTP/1.1\r\n"),
	} {
		if looksLikeTLSClientHello(payload) {
			t.Errorf("%s should not read as a ClientHello", name)
		}
	}
}

// A fragmented handshake has to still be a handshake. Nothing above proves the
// pieces reassemble into something a TLS server accepts.
func TestARealHandshakeSucceedsWhenFragmented(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dmxlc3M6Ly9leGFtcGxl")
	}))
	defer server.Close()

	client := fragmentedDirectClient(false)
	transport, _ := client.Transport.(*http.Transport)
	// The test server's certificate is its own; trusting it is not the same as
	// skipping verification, which the assertions above forbid.
	transport.TLSClientConfig = &tls.Config{RootCAs: certPoolFor(t, server)}

	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("a fragmented handshake did not complete: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "dmxlc3M6Ly9leGFtcGxl" {
		t.Fatalf("got %q", body)
	}
}

func certPoolFor(t *testing.T, server *httptest.Server) *x509.CertPool {
	t.Helper()
	return server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

// The failure this exists for, reproduced offline: something in the path reads
// the first segment, finds the hostname, and cuts the connection. It is what
// produces "first record does not look like a TLS handshake" — the client is
// answered with something that is not TLS.
func TestAMiddleboxThatCutsOnTheFirstSegmentIsDefeated(t *testing.T) {
	const hostname = "blocked.example.org"

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var blocked, allowed int32
	var mu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				segment := make([]byte, 4096)
				n, err := conn.Read(segment)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if bytes.Contains(segment[:n], []byte(hostname)) {
					// Found it in one segment: answer with something that is
					// not TLS, exactly as the real one does.
					blocked++
					_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
				allowed++
			}(conn)
		}
	}()

	dial := func(fragment bool) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hello := clientHello(hostname)
		if fragment {
			wrapped := &fragmentingConn{Conn: conn}
			_, _ = wrapped.Write(hello)
		} else {
			_, _ = conn.Write(hello)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(conn)
	}

	dial(false)
	dial(true)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if blocked != 1 {
		t.Fatalf("the unfragmented handshake should have been caught, blocked=%d", blocked)
	}
	if allowed != 1 {
		t.Fatalf("the fragmented handshake should have got past, allowed=%d", allowed)
	}
}

// A 404 is not something a differently-shaped handshake fixes. Retrying it would
// be a second wait for the same answer.
func TestAnOrdinaryFailureIsNotRetriedFragmented(t *testing.T) {
	var requests int32
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	app := &App{}
	_, err := app.fetchSubscriptionDocument(context.Background(), model.V2RaySubscription{URL: server.URL})
	if err == nil {
		t.Fatal("a 404 should fail")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("the reason should survive: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("expected one request, the server saw %d", requests)
	}
}

// The count returned has to be what was actually sent. A wrapper reporting a
// whole handshake when it stopped partway would have TLS believe it was in a
// state it is not.
func TestAShortWriteReportsWhatItSent(t *testing.T) {
	stop := &stoppingConn{after: 20}
	written, err := writeInFragments(stop, clientHello("cf.example.org"))
	if err == nil {
		t.Fatal("expected the underlying write to fail")
	}
	if written != stop.sent {
		t.Fatalf("reported %d bytes, sent %d", written, stop.sent)
	}
	if written == 0 || written > 40 {
		t.Fatalf("expected a partial write near the cut-off, got %d", written)
	}
}

type stoppingConn struct {
	net.Conn
	after int
	sent  int
}

func (c *stoppingConn) Write(p []byte) (int, error) {
	if c.sent >= c.after {
		return 0, errors.New("connection reset by peer")
	}
	c.sent += len(p)
	return len(p), nil
}

package main

// Getting a ClientHello past a middlebox that is reading it.
//
// One subscription stayed unreachable after everything else here was tried. It
// failed with
//
//	tls: first record does not look like a TLS handshake
//
// which says the reply was not TLS — something answered in place of the server.
// The same address answers with a valid certificate and the right content from
// another network, and the same subscription came through on iOS. Two clients,
// one network, two different failures: the difference is not the network, it is
// what the client puts on the wire.
//
// A ClientHello carries the hostname in the clear, in the SNI extension, and
// arrives in one TCP segment. That is all a filter needs — it reads the name out
// of the first segment and cuts the connection. Nothing later in the handshake
// matters, and neither the tunnel nor skipping certificate verification helps,
// because the connection never survives long enough to have a certificate.
//
// Splitting that first write into pieces too small to hold the name means no
// single segment contains it. A filter that matches on one segment finds
// nothing to match; the server reassembles the stream and reads the same
// ClientHello it always would. Nothing about the handshake changes — only how
// many packets it arrives in.
//
// This runs only after a direct fetch has already failed in the way interference
// looks like, so a working network never pays for it.

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	// Small enough that no piece can hold a hostname worth matching on. The
	// shortest name anyone filters is longer than this.
	minFragmentSize = 3
	maxFragmentSize = 7

	// Enough of a gap that the pieces leave as separate segments rather than
	// being gathered up by the kernel on their way out.
	fragmentDelay = time.Millisecond
)

// fragmentedDirectClient is a client that splits its ClientHello.
//
// Direct, not through the tunnel: this exists for the case where there is no
// tunnel yet, which is exactly when a subscription cannot be fetched.
func fragmentedDirectClient(skipVerify bool) *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil
	}
	// A clone. The default transport is the whole app's, and giving every
	// request in the process a fragmenting dialer to fix one fetch would be a
	// cost paid forever for a problem that lasts one call.
	transport := base.Clone()
	transport.DialContext = fragmentingDialContext

	if skipVerify {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	return &http.Client{Transport: transport}
}

func fragmentingDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	// Nagle's algorithm exists to gather small writes into one segment, which is
	// precisely what this is trying to avoid — with it on, the pieces would be
	// coalesced back into the single segment the filter is waiting for. Go sets
	// this already; it is set again here because everything below depends on it
	// and a silent default is a poor thing to depend on.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	return &fragmentingConn{Conn: conn}, nil
}

// fragmentingConn splits the first write, and only if it is a ClientHello.
//
// Only the first, because the handshake is the only part sent in the clear —
// everything after it is encrypted and carries nothing to match on. Splitting
// those too would slow every byte of the response down for no gain.
type fragmentingConn struct {
	net.Conn
	handled atomic.Bool
}

func (c *fragmentingConn) Write(payload []byte) (int, error) {
	if c.handled.CompareAndSwap(false, true) && looksLikeTLSClientHello(payload) {
		return writeInFragments(c.Conn, payload)
	}
	return c.Conn.Write(payload)
}

// writeInFragments sends payload as pieces too small to match on.
//
// The count returned is what was actually written, including on a short write.
// A wrapper that reports more than it sent would have the caller believe a
// handshake went out whole when it stopped partway.
func writeInFragments(conn net.Conn, payload []byte) (int, error) {
	written := 0
	for written < len(payload) {
		size := minFragmentSize + rand.Intn(maxFragmentSize-minFragmentSize+1)
		if remaining := len(payload) - written; size > remaining {
			size = remaining
		}
		n, err := conn.Write(payload[written : written+size])
		written += n
		if err != nil {
			return written, err
		}
		if written < len(payload) {
			time.Sleep(fragmentDelay)
		}
	}
	return written, nil
}

// looksLikeTLSClientHello reports whether these bytes open a TLS handshake.
//
//	0x16        record type: handshake
//	0x03 ..     protocol major version 3 — every TLS version on the wire
//	.. .. ..    record length
//	0x01        handshake type: client_hello
//
// The minor version and the length are not checked. TLS 1.3 sends 0x0301 here
// for compatibility with middleboxes that reject anything else, so a client that
// insisted on the real version would refuse to recognise its own handshake.
func looksLikeTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

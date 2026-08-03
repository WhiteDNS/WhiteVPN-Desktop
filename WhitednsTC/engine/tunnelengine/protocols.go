package tunnelengine

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

func testTCP(ctx context.Context, req ScanRequest, timeout time.Duration) TCPResult {
	attempts := make([]AttemptMetric, 0, req.Retries)
	var successes []int64
	for i := 0; i < req.Retries; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", endpoint(req.Host, req.Port))
		elapsed := time.Since(start).Milliseconds()
		if err != nil {
			attempts = append(attempts, AttemptMetric{Success: false, DurationMs: elapsed, ErrorCategory: classifyErr(err)})
			continue
		}
		_ = conn.Close()
		successes = append(successes, elapsed)
		attempts = append(attempts, AttemptMetric{Success: true, DurationMs: elapsed})
		if !sleepContext(ctx, minDuration(75*time.Millisecond, timeout/8)) {
			break
		}
	}
	median := median(successes)
	return TCPResult{Success: len(successes) > 0, Attempts: attempts, MedianRTTMs: median, Consistency: successRatio(attempts), ErrorCategory: firstErr(attempts)}
}

func testTLS(ctx context.Context, req ScanRequest, timeout time.Duration) TLSResult {
	host := req.SNI
	if host == "" {
		host = req.Host
	}
	conf := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h3", "h2", "http/1.1"},
		InsecureSkipVerify: req.AllowInsecureCert,
		MinVersion:         tls.VersionTLS10,
	}
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", endpoint(req.Host, req.Port))
	if err != nil {
		return TLSResult{ErrorCategory: classifyErr(err)}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	conn := tls.Client(raw, conf)
	err = conn.HandshakeContext(ctx)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return TLSResult{HandshakeMs: elapsed, ErrorCategory: classifyErr(err)}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	result := TLSResult{
		Success:     true,
		HandshakeMs: elapsed,
		Version:     tlsVersion(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
		Verified:    !req.AllowInsecureCert && len(state.VerifiedChains) > 0,
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertificateCN = cert.Subject.CommonName
		result.CertificateSANs = append(result.CertificateSANs, cert.DNSNames...)
	}
	return result
}

func testHTTP(ctx context.Context, req ScanRequest, timeout time.Duration) HTTPResult {
	scheme := "http"
	if req.Port == 443 || req.Port == 8443 || req.Port == 2053 {
		scheme = "https"
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:       &tls.Config{ServerName: chooseSNI(req), InsecureSkipVerify: req.AllowInsecureCert, NextProtos: []string{"h2", "http/1.1"}},
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		IdleConnTimeout:       timeout,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: minDuration(time.Second, timeout),
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}
	var probes []HTTPProbe
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		if ctx.Err() != nil {
			break
		}
		target := (&url.URL{Scheme: scheme, Host: endpoint(req.Host, req.Port), Path: firstPath(req.HTTPPaths)}).String()
		start := time.Now()
		httpReq, _ := http.NewRequestWithContext(ctx, method, target, nil)
		httpReq.Header.Set("User-Agent", "WhiteDnsTC/1.0")
		resp, err := client.Do(httpReq)
		elapsed := time.Since(start).Milliseconds()
		probe := HTTPProbe{Method: method, URL: target, DurationMs: elapsed}
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			probe.ErrorCategory = classifyErr(err)
		} else {
			probe.StatusCode = resp.StatusCode
			probe.Redirected = resp.StatusCode >= 300 && resp.StatusCode < 400
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
		}
		probes = append(probes, probe)
	}
	success := false
	for _, p := range probes {
		if p.StatusCode > 0 && p.StatusCode < 500 {
			success = true
		}
	}
	return HTTPResult{Success: success, Probes: probes}
}

func testWebSocket(ctx context.Context, req ScanRequest, timeout time.Duration) WSResult {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", endpoint(req.Host, req.Port))
	if err != nil {
		return WSResult{ErrorCategory: classifyErr(err)}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	conn := raw
	if req.Port == 443 || req.Port == 8443 {
		tlsConn := tls.Client(raw, &tls.Config{ServerName: chooseSNI(req), InsecureSkipVerify: req.AllowInsecureCert, NextProtos: []string{"http/1.1"}})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return WSResult{ErrorCategory: classifyErr(err)}
		}
		conn = tlsConn
	}
	key := wsKey()
	start := time.Now()
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: WhiteDnsTC/1.0\r\n\r\n", endpoint(req.Host, req.Port), key)
	if _, err := conn.Write([]byte(request)); err != nil {
		return WSResult{DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return WSResult{DurationMs: elapsed, ErrorCategory: classifyErr(err)}
	}
	_ = resp.Body.Close()
	accepted := resp.StatusCode == http.StatusSwitchingProtocols && strings.EqualFold(resp.Header.Get("Upgrade"), "websocket")
	if accepted && resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		accepted = false
	}
	return WSResult{Success: accepted, StatusCode: resp.StatusCode, DurationMs: elapsed}
}

func testUDP(ctx context.Context, req ScanRequest, timeout time.Duration) UDPResult {
	attempts := make([]AttemptMetric, 0, req.Retries)
	for i := 0; i < req.Retries; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "udp", endpoint(req.Host, req.Port))
		if err != nil {
			attempts = append(attempts, AttemptMetric{Success: false, DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)})
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte{0}); err != nil {
			_ = conn.Close()
			attempts = append(attempts, AttemptMetric{Success: false, DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)})
			continue
		}
		buf := make([]byte, 1200)
		_, err = conn.Read(buf)
		_ = conn.Close()
		attempts = append(attempts, AttemptMetric{Success: err == nil, DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)})
	}
	return UDPResult{Reachable: successRatio(attempts) > 0, Attempts: attempts, ErrorCategory: firstErr(attempts)}
}

func testQUIC(ctx context.Context, req ScanRequest, timeout time.Duration) QUICResult {
	tlsConf := &tls.Config{ServerName: chooseSNI(req), InsecureSkipVerify: req.AllowInsecureCert, NextProtos: []string{"h3"}}
	quicConf := &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout}
	start := time.Now()
	conn, err := quic.DialAddr(ctx, endpoint(req.Host, req.Port), tlsConf, quicConf)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return QUICResult{HandshakeMs: elapsed, ErrorCategory: classifyErr(err)}
	}
	state := conn.ConnectionState().TLS
	_ = conn.CloseWithError(0, "probe complete")
	return QUICResult{Success: true, HandshakeMs: elapsed, ALPN: state.NegotiatedProtocol}
}

func testDNS(ctx context.Context, req ScanRequest, timeout time.Duration) DNSResult {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	_ = builder.StartQuestions()
	_ = builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(req.DNSQuestion), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	packet, _ := builder.Finish()
	res := DNSResult{}
	for _, network := range []string{"udp", "tcp"} {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, network, endpoint(req.Host, req.Port))
		if err != nil {
			res.Attempts = append(res.Attempts, AttemptMetric{Success: false, DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)})
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		payload := packet
		if network == "tcp" {
			payload = append([]byte{byte(len(packet) >> 8), byte(len(packet))}, packet...)
		}
		if _, err = conn.Write(payload); err != nil {
			_ = conn.Close()
			res.Attempts = append(res.Attempts, AttemptMetric{Success: false, DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)})
			continue
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		_ = conn.Close()
		success := err == nil && n > 0
		res.Attempts = append(res.Attempts, AttemptMetric{Success: success, DurationMs: time.Since(start).Milliseconds(), ErrorCategory: classifyErr(err)})
		if success && network == "udp" {
			res.UDPResponsive = true
			res.Answers = append(res.Answers, parseDNSAnswers(buf[:n])...)
		}
		if success && network == "tcp" {
			res.TCPResponsive = true
			if n > 2 {
				res.Answers = append(res.Answers, parseDNSAnswers(buf[2:n])...)
			}
		}
	}
	res.ErrorCategory = firstErr(res.Attempts)
	return res
}

func endpoint(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func chooseSNI(req ScanRequest) string {
	if req.SNI != "" {
		return req.SNI
	}
	return req.Host
}

func firstPath(paths []string) string {
	if len(paths) == 0 || paths[0] == "" {
		return "/"
	}
	if strings.HasPrefix(paths[0], "/") {
		return paths[0]
	}
	return "/" + paths[0]
}

func median(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[len(values)/2]
}

func successRatio(attempts []AttemptMetric) float64 {
	if len(attempts) == 0 {
		return 0
	}
	ok := 0
	for _, a := range attempts {
		if a.Success {
			ok++
		}
	}
	return float64(ok) / float64(len(attempts))
}

func firstErr(attempts []AttemptMetric) string {
	for _, a := range attempts {
		if !a.Success && a.ErrorCategory != "" {
			return a.ErrorCategory
		}
	}
	return ""
}

func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "too many open files") ||
		strings.Contains(message, "too many open connections") ||
		strings.Contains(message, "cannot assign requested address") ||
		strings.Contains(message, "address already in use") ||
		strings.Contains(message, "only one usage of each socket address") ||
		strings.Contains(message, "lacked sufficient buffer space") ||
		strings.Contains(message, "no buffer space available") {
		return "socket_pressure"
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(message, "timeout") || strings.Contains(message, "i/o timeout") {
		return "timeout"
	}
	if strings.Contains(message, "connection refused") {
		return "refused"
	}
	if strings.Contains(message, "no such host") {
		return "dns_resolution_failed"
	}
	if strings.Contains(message, "certificate") {
		return "tls_certificate"
	}
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "unknown"
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func wsKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func parseDNSAnswers(packet []byte) []string {
	var parser dnsmessage.Parser
	if _, err := parser.Start(packet); err != nil {
		return nil
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil
	}
	var answers []string
	for {
		h, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := parser.AResource()
			if err == nil {
				answers = append(answers, net.IP(a.A[:]).String())
			}
		case dnsmessage.TypeAAAA:
			a, err := parser.AAAAResource()
			if err == nil {
				answers = append(answers, net.IP(a.AAAA[:]).String())
			}
		default:
			_ = parser.SkipAnswer()
		}
	}
	return answers
}

package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"whitevpn-desktop/internal/fragment"
	"whitevpn-desktop/internal/mihomoconf"
)

type tlsHeaderListener struct {
	net.Listener
	lengths chan int
}

func (l tlsHeaderListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsHeaderConn{Conn: c, lengths: l.lengths}, nil
}

type tlsHeaderConn struct {
	net.Conn
	header   []byte
	lengths  chan int
	recorded bool
}

func (c *tlsHeaderConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.recorded {
		needed := 5 - len(c.header)
		if needed > n {
			needed = n
		}
		c.header = append(c.header, p[:needed]...)
		if len(c.header) == 5 {
			c.recorded = true
			if c.header[0] == 22 {
				select {
				case c.lengths <- int(binary.BigEndian.Uint16(c.header[3:5])):
				default:
				}
			}
		}
	}
	return n, err
}

// This checks bytes received by a real TLS server, rather than accepting a
// configuration key as evidence that the engine actually fragments traffic.
// The HTTPS proxy terminates the tunnel locally; it never dials the internet.
func TestRealCoreFragmentsTLSHelloAndCarriesTraffic(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint("enabled=", enabled), func(t *testing.T) {
			lengths := make(chan int, 32)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect {
					http.Error(w, "CONNECT required", 405)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				if rw.Flush() != nil {
					return
				}
				request, err := http.ReadRequest(rw.Reader)
				if err != nil {
					return
				}
				request.Body.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfragment-ok")
			}))
			upstream.Listener = tlsHeaderListener{Listener: upstream.Listener, lengths: lengths}
			upstream.StartTLS()
			defer upstream.Close()
			host, portText, _ := net.SplitHostPort(upstream.Listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			proxies := []mihomoconf.Proxy{{"name": "Local TLS", "type": "http", "server": host, "port": port, "tls": true, "skip-cert-verify": true}}
			s := fragment.Default()
			s.Enabled = enabled
			proxies, err := mihomoconf.ApplyFragments(proxies, s)
			if err != nil {
				t.Fatal(err)
			}
			freePort := func() int {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				p := l.Addr().(*net.TCPAddr).Port
				l.Close()
				return p
			}
			mixed, control := freePort(), freePort()
			raw, err := yaml.Marshal(map[string]any{"proxies": proxies, "proxy-groups": []any{map[string]any{"name": mihomoconf.SelectGroup, "type": "select", "proxies": []string{"Local TLS"}}}, "rules": []string{"MATCH," + mihomoconf.SelectGroup}})
			if err != nil {
				t.Fatal(err)
			}
			config := mihomoconf.Render(string(raw), mihomoconf.Options{MixedPort: mixed, ControlPort: control, Secret: "local-test"})
			home := t.TempDir()
			configPath := filepath.Join(home, "config.yaml")
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			proc := spawnReal(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := proc.Init(ctx, home, 36); err != nil {
				t.Fatal(err)
			}
			if err := proc.SetupConfig(ctx, map[string]string{}, "http://127.0.0.1:9/"); err != nil {
				t.Fatal(err)
			}
			if err := proc.StartListener(ctx); err != nil {
				t.Fatal(err)
			}
			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixed))
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			response, err := client.Get("http://127.0.0.1:9/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(bufio.NewReader(response.Body))
			response.Body.Close()
			if err != nil || strings.TrimSpace(string(body)) != "fragment-ok" {
				t.Fatalf("traffic failed: %q %v", body, err)
			}
			select {
			case first := <-lengths:
				if enabled && (first < 13 || first > 23) {
					t.Fatalf("TLS hello was not fragmented: first record=%d", first)
				}
				if !enabled && first <= 23 {
					t.Fatalf("control unexpectedly fragmented: %d", first)
				}
				t.Logf("first TLS record=%d bytes; HTTP payload delivered", first)
			case <-ctx.Done():
				t.Fatal("server did not observe TLS ClientHello")
			}
		})
	}
}

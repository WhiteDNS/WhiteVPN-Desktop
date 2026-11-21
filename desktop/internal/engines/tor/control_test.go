package tor

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

// Port of Android's TorControlConnectionTest. The keys are spelled out again
// here so the test does not check the implementation against itself.
func hmacSHA256(key string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return mac.Sum(nil)
}

func exerciseController(t *testing.T, validServer bool) ([]string, error) {
	t.Helper()
	cookie := bytes.Repeat([]byte{7}, 32)
	serverNonce := bytes.Repeat([]byte{9}, 32)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	commands := make(chan []string, 1)
	go func() {
		var seen []string
		defer func() { commands <- seen }()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		input := bufio.NewReader(conn)
		read := func() (string, bool) {
			l, err := input.ReadString('\n')
			if err != nil {
				return "", false
			}
			if !strings.HasSuffix(l, "\r\n") {
				t.Errorf("command %q not CRLF-terminated", l)
			}
			l = strings.TrimSuffix(l, "\r\n")
			seen = append(seen, l)
			return l, true
		}
		challenge, ok := read()
		if !ok {
			return
		}
		nonce, _ := hex.DecodeString(challenge[strings.LastIndexByte(challenge, ' ')+1:])
		data := append(append(append([]byte{}, cookie...), nonce...), serverNonce...)
		serverHash := make([]byte, 32)
		if validServer {
			serverHash = hmacSHA256("Tor safe cookie authentication server-to-controller hash", data)
		}
		conn.Write([]byte("250 AUTHCHALLENGE SERVERHASH=" + hex.EncodeToString(serverHash) + " SERVERNONCE=" + hex.EncodeToString(serverNonce) + "\r\n"))
		authenticate, ok := read()
		if !ok {
			return
		}
		if want := "AUTHENTICATE " + hex.EncodeToString(hmacSHA256("Tor safe cookie authentication controller-to-server hash", data)); authenticate != want {
			t.Errorf("got %q, want %q", authenticate, want)
		}
		conn.Write([]byte("250 OK\r\n"))
		if ownership, ok := read(); ok && ownership == "TAKEOWNERSHIP" {
			conn.Write([]byte("250 OK\r\n"))
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	attachErr := attachController(conn, cookie)
	conn.Close()
	return <-commands, attachErr
}

func TestAuthenticatesControllerBeforeTakingOwnership(t *testing.T) {
	seen, err := exerciseController(t, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || !strings.HasPrefix(seen[0], "AUTHCHALLENGE SAFECOOKIE ") || len(seen[0]) != len("AUTHCHALLENGE SAFECOOKIE ")+64 || seen[2] != "TAKEOWNERSHIP" {
		t.Fatalf("commands: %q", seen)
	}
}

func TestForgedControllerNeverReceivesClientAuthentication(t *testing.T) {
	seen, err := exerciseController(t, false)
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("forged server accepted: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("forged server received %q", seen)
	}
}

func TestInvalidCookieIsRefusedBeforeConnecting(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	if err := attachController(client, make([]byte, 31)); err == nil {
		t.Fatal("short cookie accepted")
	}
}

package tor

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
)

// The test binary doubles as a fake tor.exe: Start re-executes it with this
// variable set, and it behaves like Tor as far as the controller can see.
const fakeTorEnv = "WHITEVPN_FAKE_TOR"

func TestMain(m *testing.M) {
	switch mode := os.Getenv(fakeTorEnv); mode {
	case "":
		os.Exit(m.Run())
	case "transport":
		time.Sleep(time.Minute)
	default:
		os.Exit(fakeTor(mode))
	}
}

func fakeTor(mode string) int {
	args := os.Args[1:]
	if len(args) != 4 || args[0] != "--__OwningControllerProcess" || args[1] != strconv.Itoa(os.Getppid()) || args[2] != "-f" {
		fmt.Println("[err] unexpected arguments")
		return 1
	}
	raw, err := os.ReadFile(args[3])
	if err != nil {
		return 1
	}
	var socks, control, dataDir string
	for _, l := range strings.Split(string(raw), "\n") {
		k, v, _ := strings.Cut(l, " ")
		switch k {
		case "SocksPort":
			socks = v
		case "ControlPort":
			control = v
		case "DataDirectory":
			dataDir, _ = strconv.Unquote(v)
		}
	}
	fmt.Println("Nov 20 10:00:00.000 [notice] Bootstrapped 0% (starting): Starting")
	if mode == "exit" {
		return 1
	}
	if mode == "child" {
		transport := exec.Command(os.Args[0])
		transport.Env = append(os.Environ(), fakeTorEnv+"=transport")
		if transport.Start() != nil {
			return 1
		}
	}
	socksListener, err := net.Listen("tcp", socks)
	if err != nil {
		return 1
	}
	go func() {
		for {
			c, err := socksListener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	controlListener, err := net.Listen("tcp", control)
	if err != nil {
		return 1
	}
	cookie := make([]byte, 32)
	rand.Read(cookie)
	if os.WriteFile(filepath.Join(dataDir, "control_auth_cookie"), cookie, 0o600) != nil {
		return 1
	}
	conn, err := controlListener.Accept()
	if err != nil {
		return 1
	}
	input := bufio.NewReader(conn)
	read := func() string { l, _ := input.ReadString('\n'); return strings.TrimSuffix(l, "\r\n") }
	clientNonce, _ := hex.DecodeString(strings.TrimPrefix(read(), "AUTHCHALLENGE SAFECOOKIE "))
	serverNonce := make([]byte, 32)
	rand.Read(serverNonce)
	data := append(append(append([]byte{}, cookie...), clientNonce...), serverNonce...)
	fmt.Fprintf(conn, "250 AUTHCHALLENGE SERVERHASH=%s SERVERNONCE=%s\r\n", hex.EncodeToString(safeCookieHMAC(safeCookieServerKey, data)), hex.EncodeToString(serverNonce))
	if read() != "AUTHENTICATE "+hex.EncodeToString(safeCookieHMAC(safeCookieClientKey, data)) {
		fmt.Fprint(conn, "515 Authentication failed\r\n")
		return 1
	}
	fmt.Fprint(conn, "250 OK\r\n")
	if read() != "TAKEOWNERSHIP" {
		return 1
	}
	fmt.Fprint(conn, "250 OK\r\n")
	fmt.Println("Nov 20 10:00:01.000 [warn] Could not connect to bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=secret")
	if mode != "stall" {
		fmt.Println("Nov 20 10:00:02.000 [notice] Bootstrapped 50% (loading_descriptors): Loading relay descriptors")
		fmt.Println("Nov 20 10:00:03.000 [notice] Bootstrapped 100% (done): Done")
	}
	// Like Tor after TAKEOWNERSHIP: leave once the owner's connection closes.
	for read() != "" {
	}
	if mode == "stubborn" {
		time.Sleep(time.Minute)
	}
	return 0
}

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func fastTimeouts(t *testing.T) {
	a, b, s, c := attachTimeout, bootstrapTimeout, socksTimeout, stopTimeout
	// The graceful stop is generous: under -race on a busy CI runner the fake
	// takes more than a second to notice its owner left, and a kill is a failure.
	attachTimeout, bootstrapTimeout, socksTimeout, stopTimeout = 5*time.Second, 5*time.Second, 5*time.Second, 10*time.Second
	t.Cleanup(func() { attachTimeout, bootstrapTimeout, socksTimeout, stopTimeout = a, b, s, c })
}

func startFake(t *testing.T, ctx context.Context, mode string, log *logs, progress func(int)) (*Process, error) {
	t.Helper()
	fastTimeouts(t)
	t.Setenv(fakeTorEnv, mode)
	return Start(ctx, Options{
		TorPath:  os.Args[0],
		DataDir:  t.TempDir(),
		Config:   engineprofiles.TorConfig{BridgeMode: "none"},
		Logf:     log.logf,
		Progress: progress,
	})
}

func TestStartBootstrapsAndClosesGracefully(t *testing.T) {
	log := &logs{}
	var seen []int
	var mu sync.Mutex
	p, err := startFake(t, context.Background(), "ok", log, func(percent int) { mu.Lock(); seen = append(seen, percent); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.SOCKSPort())))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	if _, err := os.Stat(p.torrc); !os.IsNotExist(err) {
		t.Error("torrc left behind")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	mu.Lock()
	if fmt.Sprint(seen) != "[0 50]" {
		t.Errorf("progress %v", seen)
	}
	mu.Unlock()
	out := log.String()
	if !strings.Contains(out, "Bootstrapped 100%") || !strings.Contains(out, "[warn] Could not connect to bridge") {
		t.Errorf("expected lines missing:\n%s", out)
	}
	for _, secret := range []string{"192.0.2.1", "0123456789ABCDEF", "cert=", "secret", "Nov 20"} {
		if strings.Contains(out, secret) {
			t.Errorf("log carries %q:\n%s", secret, out)
		}
	}
}

func TestStartFailsWhenTorExitsEarly(t *testing.T) {
	_, err := startFake(t, context.Background(), "exit", &logs{}, nil)
	if err == nil || !strings.Contains(err.Error(), "Tor exited before controller startup") {
		t.Fatalf("got %v", err)
	}
}

func TestBootstrapTimeoutStopsTorGracefully(t *testing.T) {
	fastTimeouts(t)
	bootstrapTimeout = 500 * time.Millisecond
	t.Setenv(fakeTorEnv, "stall")
	_, err := Start(context.Background(), Options{TorPath: os.Args[0], DataDir: t.TempDir(), Config: engineprofiles.TorConfig{BridgeMode: "none"}})
	if err == nil || !strings.Contains(err.Error(), "bootstrap did not finish") || strings.Contains(err.Error(), "killed") {
		t.Fatalf("got %v", err)
	}
}

func TestCancelledStartStopsTor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_, err := startFake(t, ctx, "stall", &logs{}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "killed") {
		t.Fatalf("got %v", err)
	}
}

func TestForcedStopIsReportedAndSticky(t *testing.T) {
	p, err := startFake(t, context.Background(), "stubborn", &logs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stopTimeout = time.Second // this fake never leaves, so waiting longer proves nothing
	if err := p.Close(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("got %v", err)
	}
	<-p.Done()
	if err := p.Close(); err == nil {
		t.Fatal("a forced stop was later reported clean")
	}
}

func TestTransportOutlivingTorIsEnded(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("transports are tracked by PID on Windows only")
	}
	log := &logs{}
	p, err := startFake(t, context.Background(), "child", log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.children) != 1 {
		p.Close()
		t.Fatalf("tracked %d transports, want 1", len(p.children))
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "outlived Tor") {
		t.Fatalf("leftover transport not ended:\n%s", log)
	}
}

// realTor is the staged Tor Expert Bundle, when scripts/build-tor-engine.sh
// has been run.
func realTor(t *testing.T) string {
	dir, _ := filepath.Abs(filepath.Join("..", "..", "..", "cores", "tor-windows-amd64"))
	if runtime.GOOS != "windows" {
		t.Skip("the staged Tor is windows/amd64")
	}
	if _, err := os.Stat(filepath.Join(dir, "tor.exe")); err != nil {
		t.Skip("cores/tor-windows-amd64 not staged; run scripts/build-tor-engine.sh")
	}
	return dir
}

// The real Tor parses every torrc shape we write, Windows plugin paths
// included, without touching the network.
func TestRealTorAcceptsTorrc(t *testing.T) {
	dir := realTor(t)
	for _, transport := range []string{"", "obfs4", "snowflake", "conjure"} {
		mode := "default"
		if transport == "" {
			mode = "none"
		}
		data := t.TempDir()
		config, err := buildTorrc(engineprofiles.TorConfig{BridgeMode: mode, Transport: transport}, dir, data, 9050, DefaultBridges)
		if err != nil {
			t.Fatal(err)
		}
		torrc := filepath.Join(data, "torrc")
		if err := os.WriteFile(torrc, []byte(config+"ControlPort 127.0.0.1:9051\nCookieAuthentication 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(dir, "tor.exe"), "--verify-config", "-f", torrc)
		configureCommand(cmd)
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "Configuration was valid") {
			t.Errorf("%s: %v\n%s", mode+"/"+transport, err, out)
		}
	}
}

// With the network disabled Tor can never bootstrap, so reaching the bootstrap
// timeout proves the controller attached: cookie, SAFECOOKIE and TAKEOWNERSHIP.
// The stop that follows is graceful only because Tor honoured the ownership.
func TestRealTorAttachesController(t *testing.T) {
	dir := realTor(t)
	fastTimeouts(t)
	attachTimeout, bootstrapTimeout, stopTimeout = 20*time.Second, 3*time.Second, 10*time.Second
	for _, transport := range []string{"", "obfs4"} {
		mode := "default"
		if transport == "" {
			mode = "none"
		}
		log := &logs{}
		_, err := start(context.Background(), Options{
			TorPath:        filepath.Join(dir, "tor.exe"),
			PluginDir:      dir,
			DataDir:        t.TempDir(),
			Config:         engineprofiles.TorConfig{BridgeMode: mode, Transport: transport},
			DefaultBridges: DefaultBridges,
			Logf:           log.logf,
		}, "DisableNetwork 1\n")
		if err == nil || !strings.Contains(err.Error(), "bootstrap did not finish") || strings.Contains(err.Error(), "killed") || strings.Contains(err.Error(), "could not") {
			t.Fatalf("%s: got %v\n%s", mode, err, log)
		}
		t.Logf("%s: %v\n%s", mode, err, log)
		if strings.Contains(log.String(), "obfs4 ") {
			t.Errorf("%s: bridge line logged:\n%s", mode, log)
		}
	}
}

func TestTorPathAvoidsSpaces(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("short names are a Windows feature")
	}
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	short := torPath(dir)
	if short == dir {
		t.Skip("8.3 names are disabled on this volume")
	}
	if strings.ContainsRune(short, ' ') {
		t.Fatalf("short path %q still has a space", short)
	}
	if info, err := os.Stat(short); err != nil || !info.IsDir() {
		t.Fatalf("short path %q does not resolve: %v", short, err)
	}
}

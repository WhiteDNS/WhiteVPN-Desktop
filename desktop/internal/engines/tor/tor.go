// Package tor runs Tor and its managed pluggable transports as a local SOCKS
// engine. It is a port of Android's TorEngineBackend.
package tor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
)

// Android's timeouts. Variables so tests need not wait minutes.
var (
	attachTimeout    = 10 * time.Second
	bootstrapTimeout = 180 * time.Second
	socksTimeout     = 120 * time.Second
	stopTimeout      = 5 * time.Second
)

type Options struct {
	TorPath        string                   // tor.exe
	PluginDir      string                   // dir holding lyrebird(.exe) and conjure-client(.exe)
	DataDir        string                   // per-profile, app-owned
	Config         engineprofiles.TorConfig // BridgeMode, Transport, Bridges
	DefaultBridges string                   // contents of the shipped default bridges list
	Logf           func(format string, args ...any)
	// Progress receives bootstrap percentages below 100, from Tor's output
	// goroutine. Optional.
	Progress func(percent int)
}

// Process is a running, bootstrapped Tor.
type Process struct {
	cmd          *exec.Cmd
	socksPort    int
	torrc        string
	logf         func(format string, args ...any)
	done         chan struct{}
	bootstrapped chan struct{}
	bootOnce     sync.Once

	mu       sync.Mutex
	control  net.Conn
	children []child
	// forced is sticky, as on Android: a killed Tor never stopped its
	// transports itself, so the stop is never reported as clean.
	forced bool
	closed bool
}

func (p *Process) SOCKSPort() int { return p.socksPort }

// Done is closed when tor.exe exits, for whatever reason.
func (p *Process) Done() <-chan struct{} { return p.done }

// Start launches Tor and returns once it has bootstrapped to 100% and its SOCKS
// port accepts connections.
func Start(ctx context.Context, opts Options) (*Process, error) { return start(ctx, opts, "") }

// start takes extra torrc lines so the integration test can keep a real Tor
// off the network.
func start(ctx context.Context, opts Options, extraTorrc string) (*Process, error) {
	if opts.TorPath == "" || opts.DataDir == "" {
		return nil, errors.New("tor: TorPath and DataDir are required")
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("tor: data directory: %w", err)
	}
	// The Conjure client persists its updates in ./assets; Android keeps that
	// inside the profile directory too.
	if opts.Config.Transport == "conjure" {
		if err := os.MkdirAll(filepath.Join(opts.DataDir, "assets"), 0o700); err != nil {
			return nil, fmt.Errorf("tor: data directory: %w", err)
		}
	}
	dataDir := torPath(opts.DataDir)
	pluginDir := opts.PluginDir
	if pluginDir != "" {
		pluginDir = torPath(pluginDir)
	}
	port, err := allocatePort()
	if err != nil {
		return nil, err
	}
	controlPort, err := allocatePort()
	if err != nil {
		return nil, err
	}
	config, err := buildTorrc(opts.Config, pluginDir, dataDir, port, opts.DefaultBridges)
	if err != nil {
		return nil, err
	}
	torrc := filepath.Join(dataDir, "torrc")
	config += fmt.Sprintf("ControlPort 127.0.0.1:%d\nCookieAuthentication 1\n", controlPort)
	// The Expert Bundle's geoip databases sit beside tor.exe; Tor's Windows
	// default is a literal "<default>" relative to the data directory.
	for _, geo := range [][2]string{{"GeoIPFile", "geoip"}, {"GeoIPv6File", "geoip6"}} {
		if path := filepath.Join(filepath.Dir(opts.TorPath), geo[1]); fileExists(path) {
			config += geo[0] + " " + quoteTorrc(torPath(path)) + "\n"
		}
	}
	config += extraTorrc
	if err := os.WriteFile(torrc, []byte(config), 0o600); err != nil {
		return nil, fmt.Errorf("tor: write torrc: %w", err)
	}
	cookiePath := filepath.Join(dataDir, "control_auth_cookie")
	// A cookie left by an earlier run would pass the wait below and then fail
	// SAFECOOKIE against the new Tor.
	_ = os.Remove(cookiePath)

	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	// Tor watches the owning PID and exits if this app dies without closing
	// the controller connection.
	cmd := exec.Command(opts.TorPath, "--__OwningControllerProcess", strconv.Itoa(os.Getpid()), "-f", torrc)
	cmd.Dir = dataDir
	cmd.Stdout, cmd.Stderr = w, w
	configureCommand(cmd)
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return nil, fmt.Errorf("tor: start: %w", err)
	}
	w.Close()
	p := &Process{cmd: cmd, socksPort: port, torrc: torrc, logf: logf, done: make(chan struct{}), bootstrapped: make(chan struct{})}
	go p.readOutput(r, opts.Progress)
	go func() { _ = cmd.Wait(); close(p.done) }()

	if err := p.startup(ctx, controlPort, cookiePath); err != nil {
		if cerr := p.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		return nil, err
	}
	// Transports are running by now; holding their handles lets Close confirm
	// them gone even if Tor itself dies first.
	p.mu.Lock()
	p.children = mergeChildren(p.children, childrenOf(cmd.Process.Pid))
	p.mu.Unlock()
	return p, nil
}

func (p *Process) startup(ctx context.Context, controlPort int, cookiePath string) error {
	deadline := time.Now().Add(attachTimeout)
	var cookie []byte
	for {
		if raw, err := os.ReadFile(cookiePath); err == nil && len(raw) == 32 {
			cookie = raw
			break
		}
		if err := p.pause(ctx, deadline, 100*time.Millisecond, "before controller startup"); err != nil {
			return err
		}
	}
	conn, err := p.waitForPort(ctx, controlPort, deadline)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.control = conn
	p.mu.Unlock()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := attachController(conn, cookie); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})

	timer := time.NewTimer(bootstrapTimeout)
	defer timer.Stop()
	select {
	case <-p.bootstrapped:
	case <-p.done:
		return errors.New("tor: Tor exited during bootstrap")
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("tor: bootstrap did not finish within %s", bootstrapTimeout)
	}
	socks, err := p.waitForPort(ctx, p.socksPort, time.Now().Add(socksTimeout))
	if err != nil {
		return err
	}
	return socks.Close()
}

func (p *Process) waitForPort(ctx context.Context, port int, deadline time.Time) (net.Conn, error) {
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		if err := p.pause(ctx, deadline, 150*time.Millisecond, "before connecting"); err != nil {
			return nil, err
		}
	}
}

// pause sleeps one poll interval unless Tor has exited, the caller gave up or
// the deadline passed.
func (p *Process) pause(ctx context.Context, deadline time.Time, interval time.Duration, stage string) error {
	if time.Now().After(deadline) {
		return fmt.Errorf("tor: timed out %s", stage)
	}
	select {
	case <-p.done:
		return fmt.Errorf("tor: Tor exited %s", stage)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(interval):
		return nil
	}
}

var (
	bootstrapLine = regexp.MustCompile(`Bootstrapped (\d+)%`)
	logTimestamp  = regexp.MustCompile(`^\w{3} +\d{1,2} [\d:.]+ `)
	// Addresses, fingerprints and key=value options are how bridge lines and
	// their certs would reach a log.
	sensitive = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\](:\d+)?|\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b|\b[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}\b|\b[0-9A-Fa-f]{40}\b|\S+=\S+`)
)

func (p *Process) readOutput(r io.ReadCloser, progress func(int)) {
	defer r.Close()
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		m := bootstrapLine.FindStringSubmatch(line)
		if m != nil {
			if percent, _ := strconv.Atoi(m[1]); percent == 100 {
				p.bootOnce.Do(func() { close(p.bootstrapped) })
			} else if progress != nil {
				progress(percent)
			}
		}
		if m != nil || strings.Contains(line, "[warn]") || strings.Contains(line, "[err]") {
			p.logf("tor: %s", sensitive.ReplaceAllString(logTimestamp.ReplaceAllString(line, ""), "[scrubbed]"))
		}
	}
	// Keep draining after an overlong line so Tor never blocks writing its log.
	_, _ = io.Copy(io.Discard, r)
}

// Close stops Tor and its transports. It returns nil only once both are
// confirmed gone.
func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	pid := p.cmd.Process.Pid
	select {
	case <-p.done:
	default:
		p.children = mergeChildren(p.children, childrenOf(pid))
	}
	// Graceful stop: Tor exits, terminating its transports, once the connection
	// that took ownership closes. Windows has no SIGTERM to send instead.
	grace := time.Duration(0)
	if p.control != nil {
		_ = p.control.Close()
		p.control = nil
		grace = stopTimeout
	}
	if !closedWithin(p.done, grace) {
		p.children = mergeChildren(p.children, childrenOf(pid))
		p.forced = true
		_ = p.cmd.Process.Kill()
		if !closedWithin(p.done, stopTimeout) {
			return fmt.Errorf("tor: could not stop Tor (pid %d)", pid)
		}
	}
	var stuck []child
	for _, c := range p.children {
		if !c.gone(stopTimeout) {
			c.kill()
			if !c.gone(stopTimeout) {
				stuck = append(stuck, c)
				continue
			}
			p.logf("tor: ended a transport (pid %d) that outlived Tor", c.pid)
		}
		c.release()
	}
	p.children = stuck
	if len(stuck) > 0 {
		return fmt.Errorf("tor: a transport (pid %d) could not be stopped", stuck[0].pid)
	}
	if p.forced {
		return errors.New("tor: Tor was killed, so its transports were not confirmed stopped")
	}
	_ = os.Remove(p.torrc)
	p.closed = true
	return nil
}

func closedWithin(ch <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
}

func mergeChildren(have, found []child) []child {
	for _, c := range found {
		known := false
		for _, h := range have {
			known = known || h.pid == c.pid
		}
		if known {
			c.release()
		} else {
			have = append(have, c)
		}
	}
	return have
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func allocatePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("tor: allocate port: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

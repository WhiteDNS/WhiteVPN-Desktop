package psiphon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/engines"
)

// stopTimeout bounds how long Close waits for the killed worker to be reaped.
const stopTimeout = 10 * time.Second

// BinaryName is the worker's file name in cores/, built by
// scripts/build-psiphon-engine.sh.
func BinaryName() string {
	name := fmt.Sprintf("psiphon-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// Engine is the registration for engines.Register.
func Engine() engines.Engine {
	return engines.Engine{Start: Start, Binaries: []string{BinaryName()}}
}

type process struct {
	cmd        *exec.Cmd
	configPath string
	done       chan struct{}
	connected  chan struct{}
	onceConn   sync.Once

	mu   sync.Mutex
	port int
	err  error

	closeMu sync.Mutex
}

func (p *process) SOCKSPort() int        { p.mu.Lock(); defer p.mu.Unlock(); return p.port }
func (p *process) Done() <-chan struct{} { return p.done }

// Close kills the worker and succeeds only once it has exited. The
// ConsoleClient keeps nothing but its datastore, which outlives sessions.
func (p *process) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	_ = p.cmd.Process.Kill() // an error here means it has already exited
	select {
	case <-p.done:
		_ = os.Remove(p.configPath)
		return nil
	case <-time.After(stopTimeout):
		return fmt.Errorf("psiphon: the worker did not exit")
	}
}

// Start runs the ConsoleClient with Android's config and returns once it has
// a tunnel and its SOCKS port answers (PsiphonEngineBackend.start).
func Start(ctx context.Context, opts engines.StartOptions) (engines.Process, error) {
	c := opts.Profile.Config.Psiphon
	if opts.Profile.Kind != engineprofiles.Psiphon || c == nil || opts.Binary == nil || opts.DataDir == "" {
		return nil, fmt.Errorf("psiphon: invalid start options")
	}
	logf := func(format string, args ...any) {
		if opts.Log != nil {
			opts.Log(fmt.Sprintf("Psiphon: "+format, args...))
		}
	}
	bin, err := opts.Binary(BinaryName())
	if err != nil {
		return nil, err
	}
	dataDir := filepath.Join(opts.DataDir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("psiphon: prepare data directory: %w", err)
	}
	socksPort, err := engines.FreePort()
	if err != nil {
		return nil, err
	}
	httpPort, err := engines.FreePort()
	if err != nil {
		return nil, err
	}
	config, err := BuildConfig(*c, dataDir, socksPort, httpPort)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(opts.DataDir, "config.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return nil, fmt.Errorf("psiphon: write config: %w", err)
	}

	cmd := newCommand(bin, configPath, opts.DataDir)
	notices, err := cmd.StderrPipe()
	if err != nil {
		_ = os.Remove(configPath)
		return nil, err
	}
	p := &process{cmd: cmd, configPath: configPath, done: make(chan struct{}), connected: make(chan struct{}), port: socksPort}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(configPath)
		return nil, fmt.Errorf("psiphon: start worker: %w", err)
	}
	go func() {
		p.read(notices, opts.DataDir, logf)
		_ = cmd.Wait()
		close(p.done)
	}()

	startup, cancel := context.WithTimeout(ctx, engines.StartTimeout)
	defer cancel()
	fail := func(err error) (engines.Process, error) {
		if closeErr := p.Close(); closeErr != nil {
			// The worker is still alive; hand it over so the caller can retry Close.
			return p, errors.Join(err, closeErr)
		}
		return nil, err
	}
	select {
	case <-p.connected:
	case <-p.done:
		return fail(p.failure("Psiphon stopped before connecting"))
	case <-startup.Done():
		return fail(fmt.Errorf("psiphon: not connected: %w", startup.Err()))
	}
	if err := engines.WaitForPort(startup, p.SOCKSPort(), p.done); err != nil {
		return fail(fmt.Errorf("psiphon: %w", err))
	}
	return p, nil
}

// The worker outlives the startup context, so it is not tied to one. Notices
// arrive on stderr as JSON lines.
func newCommand(bin, configPath, dir string) *exec.Cmd {
	cmd := exec.Command(bin, "-config", configPath)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	configureCommand(cmd)
	return cmd
}

func (p *process) failure(fallback string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	return errors.New("psiphon: " + fallback)
}

func (p *process) read(r io.Reader, regionsDir string, logf func(string, ...any)) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		n, ok := ParseNotice(scanner.Bytes())
		if !ok {
			continue
		}
		switch {
		case n.Type == NoticeListeningSocks:
			p.mu.Lock()
			p.port = n.Port
			p.mu.Unlock()
			logf("SOCKS proxy listening on 127.0.0.1:%d", n.Port)
		case n.Type == NoticeTunnels:
			if n.Count > 0 {
				p.onceConn.Do(func() { logf("connected"); close(p.connected) })
			}
		case n.Type == NoticeRegions:
			_ = Record(regionsDir, n.Regions)
		case n.Type == NoticeError && n.Message != "":
			logf("%s", n.Message)
		case n.Fatal():
			p.mu.Lock()
			if p.err == nil {
				p.err = fmt.Errorf("psiphon: the engine stopped (%s)", n.Type)
			}
			p.mu.Unlock()
			logf("stopped: %s", n.Type)
			// Android marks the tunnel inactive on these; ending the worker is
			// what makes Done report it here.
			_ = p.cmd.Process.Kill()
		}
	}
	// Keep draining after a scanner error so the worker never blocks on stderr.
	_, _ = io.Copy(io.Discard, r)
}

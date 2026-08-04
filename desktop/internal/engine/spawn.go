package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"time"
)

// ErrCoreExited means the core process ended before it connected back. It is
// worth distinguishing from a timeout: a core that dies on startup usually dies
// immediately, and waiting the full connect timeout for a process already gone
// turns a two second failure into a twenty second one.
var ErrCoreExited = errors.New("engine: core exited before connecting")

// SpawnOptions configures starting a core.
type SpawnOptions struct {
	// CorePath is the core executable.
	CorePath string
	// WorkingDir is where the core runs. It resolves relative paths from here,
	// including its geodata.
	WorkingDir string

	// ConnectTimeout bounds the wait for the core to dial back.
	ConnectTimeout time.Duration
	// EventBuffer sizes the client's event channel.
	EventBuffer int

	// Endpoint overrides the pipe or socket the core is told to dial. Leave empty
	// for a generated one.
	Endpoint string
	// SecurityDescriptor overrides the Windows pipe ACL. Leave empty in
	// production, where the default restricts the pipe to SYSTEM and
	// Administrators. Tests and unelevated development runs need it wider.
	SecurityDescriptor string

	// Supervise runs immediately after the core starts, so the caller can put it
	// in a job object. Without one, killing this process leaves the core running
	// with a live tunnel. It runs after rather than before because a process
	// cannot join a job until it exists; the gap is microseconds and the core has
	// not created an adapter yet, so what it can orphan has done nothing.
	Supervise func(*exec.Cmd) error

	// Stdout and Stderr receive the core's own output. Worth capturing: some
	// startup failures are only ever printed there and never reach a reply.
	Stdout io.Writer
	Stderr io.Writer
}

// Process is a running core together with the client talking to it.
type Process struct {
	*Client
	cmd      *exec.Cmd
	listener net.Listener
	exited   chan error
}

// Exited carries the core's exit status, once.
func (p *Process) Exited() <-chan error { return p.exited }

// PID is the core's process id, or zero once it has gone.
func (p *Process) PID() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Spawn starts a core and returns it connected.
//
// The core is the client of this connection, not the server: it takes an
// endpoint as its only argument and dials back. So the endpoint is created and
// listened on here first, then handed over.
func Spawn(ctx context.Context, opts SpawnOptions) (*Process, error) {
	if opts.CorePath == "" {
		return nil, errors.New("engine: CorePath is required")
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 20 * time.Second
	}

	endpoint := opts.Endpoint
	if endpoint == "" {
		generated, err := generateEndpoint()
		if err != nil {
			return nil, err
		}
		endpoint = generated
	}

	listener, err := listen(endpoint, opts.SecurityDescriptor)
	if err != nil {
		return nil, fmt.Errorf("engine: listen on %s: %w", endpoint, err)
	}

	cmd := exec.CommandContext(ctx, opts.CorePath, endpoint)
	cmd.Dir = opts.WorkingDir
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	if err := cmd.Start(); err != nil {
		_ = listener.Close()
		cleanupEndpoint(endpoint)
		return nil, fmt.Errorf("engine: start %s: %w", opts.CorePath, err)
	}

	if opts.Supervise != nil {
		if err := opts.Supervise(cmd); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			_ = listener.Close()
			cleanupEndpoint(endpoint)
			// An unsupervised core is the exact thing Supervise exists to prevent,
			// so this fails the spawn rather than carrying on without it.
			return nil, fmt.Errorf("engine: supervise: %w", err)
		}
	}

	conn, exited, err := acceptWithin(listener, cmd, opts.ConnectTimeout)
	if err != nil {
		_ = listener.Close()
		_ = cmd.Process.Kill()
		cleanupEndpoint(endpoint)
		return nil, err
	}

	return &Process{
		Client:   NewClient(conn, opts.EventBuffer),
		cmd:      cmd,
		listener: listener,
		exited:   exited,
	}, nil
}

// acceptWithin waits for the core to dial back, giving up early if it dies.
func acceptWithin(listener net.Listener, cmd *exec.Cmd, timeout time.Duration) (net.Conn, chan error, error) {
	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		accepts <- accepted{conn, err}
	}()

	exited := make(chan error, 1)
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case a := <-accepts:
		if a.err != nil {
			return nil, nil, fmt.Errorf("engine: accept: %w", a.err)
		}
		// Keep forwarding the exit status now that someone may care about it.
		go func() { exited <- <-waited }()
		return a.conn, exited, nil
	case err := <-waited:
		return nil, nil, fmt.Errorf("%w: %v", ErrCoreExited, err)
	case <-timer.C:
		return nil, nil, fmt.Errorf("engine: core did not connect within %s", timeout)
	}
}

// Stop shuts the core down, preferring a clean exit. A killed core can leave its
// tunnel adapter and routes behind, which is the mess crash recovery exists for
// and is better not created in the first place.
func (p *Process) Stop(ctx context.Context) error {
	if p.Client != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = p.Shutdown(shutdownCtx)
		cancel()
		_ = p.Client.Close()
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}

	select {
	case err := <-p.exited:
		return err
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		return errors.New("engine: core did not exit cleanly and was killed")
	case <-ctx.Done():
		_ = p.cmd.Process.Kill()
		return ctx.Err()
	}
}

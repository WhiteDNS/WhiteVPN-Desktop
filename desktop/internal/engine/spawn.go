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
	//
	// They are not honoured under Elevated: a child started through the elevation
	// prompt cannot inherit this process's pipes.
	Stdout io.Writer
	Stderr io.Writer

	// Elevated asks for the core to run as Administrator, which it must to create
	// a tunnel adapter. The user is prompted once per start.
	//
	// Only the core is elevated. The interface stays as the user, which is where
	// it belongs, and the two still meet on the same pipe because the core is the
	// side that dials.
	Elevated bool
}

// childProcess is the running core, however it was started. The elevated path
// does not produce an *exec.Cmd — the process is created by the shell on our
// behalf — so both are reached through this.
type childProcess interface {
	PID() int
	Wait() error
	Kill() error
}

// ordinaryChild wraps a normally started core.
type ordinaryChild struct{ cmd *exec.Cmd }

func (c ordinaryChild) PID() int {
	if c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}
func (c ordinaryChild) Wait() error { return c.cmd.Wait() }
func (c ordinaryChild) Kill() error {
	if c.cmd.Process == nil {
		return nil
	}
	return c.cmd.Process.Kill()
}

// Process is a running core together with the client talking to it.
type Process struct {
	*Client
	child    childProcess
	listener net.Listener
	exited   chan error
}

// Exited carries the core's exit status, once.
func (p *Process) Exited() <-chan error { return p.exited }

// PID is the core's process id, or zero once it has gone.
func (p *Process) PID() int {
	if p.child == nil {
		return 0
	}
	return p.child.PID()
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

	// A connect that has already been cancelled should not leave a core behind
	// to be cleaned up; this is what ctx is for here, and all it is for.
	if err := ctx.Err(); err != nil {
		return nil, err
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

	var child childProcess
	if opts.Elevated {
		elevated, err := startElevatedChild(opts.CorePath, endpoint, opts.WorkingDir)
		if err != nil {
			_ = listener.Close()
			cleanupEndpoint(endpoint)
			return nil, err
		}
		child = elevated
	} else {
		// exec.Command, not exec.CommandContext: ctx governs *starting* the
		// core, not how long it may live. It used to be CommandContext, which
		// meant the core was killed the moment that context was cancelled — and
		// the context handed in here is the one that lets a user cancel a
		// connect, cancelled by `defer cancel()` the instant the connect
		// function returns. So the core died a second after every successful
		// connection, in proxy mode only: the TUN path spawns through
		// ShellExecuteExW instead, which no context can reach. That is the whole
		// of "TUN works and proxy mode does not".
		//
		// Nothing depended on that kill for cleanup. Every failure path below
		// already stops the child explicitly, and so does Session.Close.
		cmd := exec.Command(opts.CorePath, endpoint)
		cmd.Dir = opts.WorkingDir
		cmd.Stdout = opts.Stdout
		cmd.Stderr = opts.Stderr
		configureCommand(cmd)
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
				// An unsupervised core is the exact thing Supervise exists to
				// prevent, so this fails the spawn rather than carrying on.
				return nil, fmt.Errorf("engine: supervise: %w", err)
			}
		}
		child = ordinaryChild{cmd: cmd}
	}

	conn, exited, err := acceptWithin(listener, child, opts.ConnectTimeout)
	if err != nil {
		_ = listener.Close()
		_ = child.Kill()
		cleanupEndpoint(endpoint)
		return nil, err
	}

	return &Process{
		Client:   NewClient(conn, opts.EventBuffer),
		child:    child,
		listener: listener,
		exited:   exited,
	}, nil
}

// acceptWithin waits for the core to dial back, giving up early if it dies.
func acceptWithin(listener net.Listener, child childProcess, timeout time.Duration) (net.Conn, chan error, error) {
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
	go func() { waited <- child.Wait() }()

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
	if p.child == nil {
		return nil
	}

	// Closing the client and the listener above is the mechanism, not merely
	// politeness: the core reads frames in a loop and returns on any read error
	// including EOF, and its main returns with it. So the pipe going away ends
	// the process, and that works whatever privileges either side holds — which
	// matters now that the interface runs unelevated while the core, in tunnel
	// mode, does not. Kill is the last resort for a core wedged badly enough
	// that it is no longer reading its own socket.
	select {
	case err := <-p.exited:
		return err
	case <-time.After(5 * time.Second):
		return p.killAfterFailedShutdown(errors.New("engine: core did not exit cleanly"))
	case <-ctx.Done():
		return p.killAfterFailedShutdown(ctx.Err())
	}
}

// killAfterFailedShutdown terminates a core that would not leave, and says so
// plainly when it cannot.
//
// An unelevated process is not allowed to terminate an elevated one, so in
// tunnel mode this can fail — and a core left running holds the tunnel adapter
// and its routes, which is the difference between "disconnected" and "the
// machine has no internet and nothing on screen explains why". Reporting it is
// the least that is owed; silently discarding the error would leave that state
// with no trace at all.
func (p *Process) killAfterFailedShutdown(cause error) error {
	if err := p.child.Kill(); err != nil {
		return fmt.Errorf("%w, and could not be stopped (%v): its tunnel may still be up — end the mihomo process (pid %d) in Task Manager", cause, err, p.PID())
	}
	return fmt.Errorf("%w and was stopped", cause)
}

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
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
	// A child started through an elevation prompt cannot inherit this process's
	// pipes, so on that path they are dropped. Where the core is started
	// directly — Windows never, Linux when the caller is already root — they
	// are honoured, which is the only case where the engine's own startup
	// complaints can be read at all.
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
	exitDone chan struct{}
	stopMu   sync.Mutex
}

// Exited carries the core's exit status, once.
func (p *Process) Exited() <-chan error { return p.exited }

// ExitDone broadcasts confirmed process exit; it is safe to observe and retry
// cleanup without consuming the one-shot exit-status channel.
func (p *Process) ExitDone() <-chan struct{} { return p.exitDone }

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
	p, err := SpawnOwned(ctx, opts)
	if err != nil {
		if p != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = p.Stop(cleanup)
			cancel()
		}
		return nil, err
	}
	return p, nil
}

// SpawnOwned returns the process even when its callback/handshake fails. The
// caller remains responsible for confirmed cleanup of that partial startup.
func SpawnOwned(ctx context.Context, opts SpawnOptions) (*Process, error) {
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
		elevated, err := startElevatedChild(opts.CorePath, endpoint, opts.WorkingDir, opts.Stdout, opts.Stderr)
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

	p := &Process{child: child, listener: listener, exited: make(chan error, 1), exitDone: make(chan struct{})}
	go func() { err := child.Wait(); p.exited <- err; close(p.exitDone) }()
	conn, err := acceptWithin(ctx, listener, p.exitDone, opts.ConnectTimeout)
	if err != nil {
		_ = listener.Close()
		cleanupEndpoint(endpoint)
		return p, err
	}
	p.Client = NewClient(conn, opts.EventBuffer)
	return p, nil
}

// acceptWithin waits for the core to dial back, giving up early if it dies.
func acceptWithin(ctx context.Context, listener net.Listener, exited <-chan struct{}, timeout time.Duration) (net.Conn, error) {
	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		accepts <- accepted{conn, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case a := <-accepts:
		if a.err != nil {
			return nil, fmt.Errorf("engine: accept: %w", a.err)
		}
		return a.conn, nil
	case <-exited:
		return nil, ErrCoreExited
	case <-timer.C:
		return nil, fmt.Errorf("engine: core did not connect within %s", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Stop shuts the core down, preferring a clean exit. A killed core can leave its
// tunnel adapter and routes behind, which is the mess crash recovery exists for
// and is better not created in the first place.
func (p *Process) Stop(ctx context.Context) error {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	select {
	case <-p.exitDone:
		if p.Client != nil {
			_ = p.Client.Close()
		}
		if p.listener != nil {
			_ = p.listener.Close()
		}
		return nil
	default:
	}
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
	case <-p.exitDone:
		return nil
	case <-time.After(5 * time.Second):
		return p.killAfterFailedShutdown(ctx, errors.New("engine: core did not exit cleanly"))
	case <-ctx.Done():
		return p.killAfterFailedShutdown(ctx, ctx.Err())
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
func (p *Process) killAfterFailedShutdown(ctx context.Context, cause error) error {
	if err := p.child.Kill(); err != nil {
		return fmt.Errorf("%w, and could not be stopped (%v): its tunnel may still be up — end the mihomo process (pid %d) in Task Manager", cause, err, p.PID())
	}
	select {
	case <-p.exitDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

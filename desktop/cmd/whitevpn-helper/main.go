//go:build linux

// whitevpn-helper is WhiteVPN's privileged component on Linux: the only thing
// this app ever asks to run as root, and the only thing that ever starts a
// root core.
//
// The trust argument, in one place:
//
//   - It is started through pkexec, so polkit decides who may run it — with
//     the desktop's own password prompt or its rules for admin users.
//   - It accepts exactly one command, start-tunnel, whose arguments name no
//     executable. The core is resolved from the fixed root-owned location the
//     package installed and validated before use; WHITEVPN_MIHOMO_BIN and
//     every other override stop at this boundary.
//   - Its environment is cleared rather than inherited. What survives is not
//     able to steer the core.
//   - It owns the core's lifetime. When the asking UI goes away — crash,
//     quit, kill — the tunnel does not outlive it: the helper notices, gives
//     the core time to tear down cleanly, then makes sure.
//
// Exit codes: 0 clean; 2 usage; 3 trusted core missing or invalid; 4 the core
// failed to start; otherwise the core's own exit status.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"whitevpn-desktop/internal/helper"
)

const (
	exitUsage  = 2
	exitNoCore = 3
	exitStart  = 4
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		return fail(exitUsage, errors.New(
			"usage: whitevpn-helper start-tunnel --socket PATH --ui-pid PID --ui-start-time TICKS [--device NAME]"))
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("whitevpn-helper protocol %d\n", helper.Version)
		return 0
	case "start-tunnel":
	default:
		return fail(exitUsage, fmt.Errorf("%q is not a command this helper knows", os.Args[1]))
	}

	request, err := helper.ParseStartTunnelArgs(os.Args[2:])
	if err != nil {
		return fail(exitUsage, err)
	}

	// The core comes from one place and nowhere else. A path from the caller —
	// an environment variable, an extracted copy beside their config — would
	// make "run as root" answer to whoever filled it in.
	install, err := helper.Detect()
	if err != nil {
		return fail(exitNoCore, fmt.Errorf("no trusted core to start: %w", err))
	}

	// Recovery before anything new: only what provably belongs to this app is
	// touched, by executable path for processes and by tuntap attributes for
	// interfaces.
	if leftovers := helper.LeftoverCorePIDs(install.CorePath); len(leftovers) > 0 {
		helper.TerminateAll(leftovers, 5*time.Second)
		stderrf("stopped leftover core process(es): %v", leftovers)
	}
	if request.Device != "" {
		if err := helper.RemoveStaleTun(request.Device); err != nil {
			// Not fatal: verification after start is what decides whether the
			// tunnel is usable. But a stale interface nobody could remove is
			// worth a line in whatever log exists.
			stderrf("could not clean up interface %s: %v", request.Device, err)
		}
	}

	core := exec.Command(install.CorePath, request.SocketPath)
	core.Dir = helper.InstallDir
	core.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}
	core.Stdout = os.Stdout
	core.Stderr = os.Stderr
	if err := core.Start(); err != nil {
		return fail(exitStart, fmt.Errorf("start %s: %w", install.CorePath, err))
	}
	return supervise(core, request)
}

// supervise watches two things and keeps neither a secret: whether the core is
// still running, and whether whoever asked for it still exists. Either failing
// ends the session, cleanly first and firmly if needed.
func supervise(core *exec.Cmd, request helper.StartRequest) int {
	done := make(chan error, 1)
	go func() { done <- core.Wait() }()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	started := time.Now()
	var firstLive time.Time

	for {
		select {
		case err := <-done:
			return exitCodeOf(err)
		case <-signals:
			stopCore(core, done)
			return 0
		case <-ticker.C:
			if !helper.AliveWithStarttime(request.UIPID, request.UIStartTime) {
				// The exact process instance that launched this session is
				// gone — start time matched, so this is not some recycled
				// number. Nothing is left to own the tunnel.
				stopCore(core, done)
				return 0
			}
			live := helper.SocketIsLive(request.SocketPath)
			if live && firstLive.IsZero() {
				firstLive = time.Now()
			}
			if !live && !firstLive.IsZero() {
				// The listener existed and has closed: that close is how the
				// control channel says the session is over.
				stopCore(core, done)
				return 0
			}
			if !live && firstLive.IsZero() &&
				time.Since(started) > time.Duration(request.StartupDeadlineSeconds)*time.Second {
				// The startup deadline: the socket never came up at all, which
				// means the thing that promised to listen never did.
				stopCore(core, done)
				return 0
			}
		}
	}
}

// stopCore asks mihomo to leave (SIGTERM tears its adapter and routes down
// properly), then insists.
func stopCore(core *exec.Cmd, done <-chan error) {
	if core.Process == nil {
		return
	}
	_ = core.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(helper.ShutdownGrace):
		_ = core.Process.Kill()
		<-done
	}
}

func exitCodeOf(err error) int {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		if err != nil {
			return exitStart
		}
		return 0
	}
	// A process ended by a signal has ExitCode() == -1, which os.Exit would
	// flatten into an anonymous 255. The shell convention keeps the cause:
	// whoever reads the pkexec exit status learns how the core actually died.
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exitErr.ExitCode()
}

func fail(code int, err error) int {
	stderrf("%v", err)
	return code
}

func stderrf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "whitevpn-helper: "+format+"\n", args...)
}

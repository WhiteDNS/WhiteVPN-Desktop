package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// Running the engine as root on Linux.
//
// A tunnel device needs CAP_NET_ADMIN, which this process does not have and
// should not: the interface runs as the user. So when a tunnel is wanted the
// engine — and only the engine — is started through pkexec, which puts the
// password prompt in the desktop's own polkit agent rather than in a terminal.
//
// As on Windows, nothing has to be handed to the elevated child: the engine is
// the side that dials, so it is given a socket path and connects back. Root
// bypasses the socket's 0600 owner-only permissions, so no widening is needed
// and the socket stays closed to every other account on the machine.
//
// pkexec clears the environment and does not inherit the caller's working
// directory, so both the core and the socket must be named absolutely. The
// caller already resolves them.

// pkexecDeclined is the exit status pkexec uses when the prompt is dismissed or
// authorisation fails. Distinguishing it matters: "the tunnel needs your
// password" is actionable where "the engine did not start" is not.
const pkexecDeclined = 126

func startElevatedChild(corePath, endpoint, workingDir string) (childProcess, error) {
	if os.Geteuid() == 0 {
		// Already root — asking again would be theatre, and starting it directly
		// keeps the engine's output, which the pkexec path cannot capture.
		cmd := exec.Command(corePath, endpoint)
		cmd.Dir = workingDir
		configureCommand(cmd)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("engine: start %s: %w", corePath, err)
		}
		return ordinaryChild{cmd: cmd}, nil
	}

	pkexecPath, err := exec.LookPath("pkexec")
	if err != nil {
		return nil, errors.New(
			"engine: a tunnel needs root and pkexec is not installed. " +
				"Install polkit, or turn the tunnel off and use the local proxy instead")
	}

	cmd := exec.Command(pkexecPath, corePath, endpoint)
	cmd.Dir = workingDir
	configureCommand(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("engine: start %s through pkexec: %w", corePath, err)
	}
	return pkexecChild{cmd: cmd}, nil
}

// pkexecChild is the core running under pkexec. It behaves like any other child
// except that its exit status carries pkexec's own codes, which are worth
// translating rather than reporting as a bare number.
type pkexecChild struct{ cmd *exec.Cmd }

func (c pkexecChild) PID() int {
	if c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

func (c pkexecChild) Wait() error {
	err := c.cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == pkexecDeclined {
		return errors.New("engine: the tunnel needs root, and the password prompt was declined")
	}
	return err
}

// Kill ends pkexec. The core it launched runs as root and is not this process's
// child to signal, so a clean shutdown has to go through the action protocol
// first; this is the fallback for when that fails, and it can leave the engine
// running where the protocol would not have.
func (c pkexecChild) Kill() error {
	if c.cmd.Process == nil {
		return nil
	}
	return c.cmd.Process.Kill()
}

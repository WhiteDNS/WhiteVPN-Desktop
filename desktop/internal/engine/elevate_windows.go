package engine

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Running the engine as Administrator.
//
// Creating a wintun adapter needs it, and this process does not have it: the
// interface runs as the user, which is where it belongs. So when a tunnel is
// wanted the engine — and only the engine — is started elevated.
//
// This works without passing any handle to the child because the engine is the
// one that dials: it is given a pipe name and connects back to it. All that is
// required is that the pipe's ACL admit an elevated process, which the default
// descriptor already does, since it grants SYSTEM and Administrators.
//
// The cost is that an elevated child started this way cannot inherit our pipes
// for stdout and stderr, so the engine's own log lines do not reach the app in
// this mode. The action protocol still works, which is what the connection
// depends on; only the diagnostics are thinner. A privileged helper service
// would fix that, and is the eventual answer — this is what makes a tunnel
// possible before that exists.

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	swHide                = 0
)

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteExW")
)

// elevatedProcess is a child started with Administrator rights. It is not an
// *exec.Cmd: the process was not created by this one in the usual sense, so only
// its handle and id are available.
type elevatedProcess struct {
	handle windows.Handle
	pid    int
}

// startElevated runs path with arguments as Administrator, prompting the user.
//
// A refused prompt is reported as such rather than as a generic failure: being
// told the tunnel needs Administrator is actionable, where "the engine did not
// start" is not.
func startElevated(path string, arguments string, workingDir string) (*elevatedProcess, error) {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return nil, err
	}
	file, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	params, err := syscall.UTF16PtrFromString(arguments)
	if err != nil {
		return nil, err
	}
	directory, err := syscall.UTF16PtrFromString(workingDir)
	if err != nil {
		return nil, err
	}

	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  directory,
		// The engine has no interface of its own, and showing its console over
		// the app is the fault this replaced.
		nShow: swHide,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))

	ret, _, callErr := procShellExecute.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == windows.ERROR_CANCELLED {
			return nil, fmt.Errorf("engine: the tunnel needs Administrator, and the prompt was declined")
		}
		return nil, fmt.Errorf("engine: could not start elevated: %w", callErr)
	}
	if info.hProcess == 0 {
		return nil, fmt.Errorf("engine: elevated start returned no process")
	}

	// A missing pid is not worth failing the start over: it is only ever used to
	// report which process is running.
	pid, _ := windows.GetProcessId(info.hProcess)
	return &elevatedProcess{handle: info.hProcess, pid: int(pid)}, nil
}

func (p *elevatedProcess) PID() int { return p.pid }

// Wait blocks until the process ends.
func (p *elevatedProcess) Wait() error {
	event, err := windows.WaitForSingleObject(p.handle, windows.INFINITE)
	if err != nil {
		return err
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("engine: unexpected wait result %d", event)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.handle, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("engine: exited with status %d", code)
	}
	return nil
}

// Kill ends the process. An elevated child cannot be signalled the polite way
// from here, so a clean shutdown has to go through the action protocol first;
// this is the fallback for when that fails.
func (p *elevatedProcess) Kill() error {
	return windows.TerminateProcess(p.handle, 1)
}

func (p *elevatedProcess) Close() {
	if p.handle != 0 {
		_ = windows.CloseHandle(p.handle)
		p.handle = 0
	}
}

// isElevated reports whether this process already has Administrator rights, in
// which case the engine can be started normally and its output captured.
func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// startElevatedChild starts the core as Administrator and returns it as an
// ordinary child from the caller's point of view.
//
// If this process is already elevated there is nothing to ask for, and starting
// normally is better: it keeps the engine's output, which the elevation prompt
// path cannot.
func startElevatedChild(corePath, endpoint, workingDir string) (childProcess, error) {
	if isElevated() {
		cmd := exec.Command(corePath, endpoint)
		cmd.Dir = workingDir
		configureCommand(cmd)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("engine: start %s: %w", corePath, err)
		}
		return ordinaryChild{cmd: cmd}, nil
	}
	return startElevated(corePath, quoteArgument(endpoint), workingDir)
}

// quoteArgument wraps the endpoint for the shell. Pipe names contain no spaces,
// but they are generated rather than fixed, and an unquoted argument that one
// day does contain one would fail in a way that looks like the core refusing to
// connect.
func quoteArgument(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

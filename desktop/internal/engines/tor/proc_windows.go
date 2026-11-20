package tor

import (
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// createNoWindow keeps tor.exe, a console program, from opening a console over
// the interface, as internal/engine does for mihomo.
const createNoWindow = 0x08000000

func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// torPath returns the 8.3 short form of an existing path that Tor could not
// take as written: ClientTransportPlugin splits on whitespace, and tor.exe
// opens files through ANSI APIs, which mangle a non-ASCII user name. Short names
// can be disabled per volume; the caller still refuses what comes back unusable.
func torPath(path string) string {
	if !strings.ContainsFunc(path, func(r rune) bool { return r > 0x7e || r <= ' ' || r == '"' || r == '\'' || r == '#' }) {
		return path
	}
	long, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return path
	}
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	n, err := syscall.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return path
	}
	return syscall.UTF16ToString(buf[:n])
}

// child is a process Tor started, held by handle so its PID cannot be reused
// under us between finding it and confirming it is gone.
type child struct {
	pid    int
	handle syscall.Handle
}

// childrenOf finds the processes Tor launched: its managed transports.
func childrenOf(pid int) []child {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snapshot)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var found []child
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		// conhost.exe hosts the hidden console and goes when Tor does.
		if int(entry.ParentProcessID) != pid || entry.ProcessID == 0 || strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), "conhost.exe") {
			continue
		}
		h, err := syscall.OpenProcess(syscall.SYNCHRONIZE|syscall.PROCESS_TERMINATE, false, entry.ProcessID)
		if err == nil {
			found = append(found, child{pid: int(entry.ProcessID), handle: h})
		}
	}
	return found
}

func (c child) gone(within time.Duration) bool {
	event, _ := syscall.WaitForSingleObject(c.handle, uint32(within/time.Millisecond))
	return event == syscall.WAIT_OBJECT_0
}

func (c child) kill() { _ = syscall.TerminateProcess(c.handle, 1) }

func (c child) release() { _ = syscall.CloseHandle(c.handle) }

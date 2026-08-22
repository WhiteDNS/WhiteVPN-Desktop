//go:build linux

package helper

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProcStartTimeOf reads field 22 of /proc/<pid>/stat: the time in clock ticks
// after boot when this exact process instance started.
//
// A PID alone identifies a slot, not a process; the start time is what makes
// "is the UI still the UI I was launched by?" answerable after an unrelated
// process has been recycled into the same number.
func ProcStartTimeOf(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The comm field may contain spaces and parentheses, so everything before
	// its closing parenthesis is skipped rather than split.
	closing := strings.LastIndex(string(raw), ")")
	if closing < 0 {
		return 0, fmt.Errorf("/proc/%d/stat is not shaped like a stat file", pid)
	}
	fields := strings.Fields(string(raw[closing+1:]))
	// fields[0] is state (field 3); starttime is field 22, so index 19 here.
	if len(fields) < 20 {
		return 0, fmt.Errorf("/proc/%d/stat has too few fields", pid)
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("starttime of %d unreadable: %w", pid, err)
	}
	return value, nil
}

// SelfStartTime is this process's own start time, for handing to someone who
// will later check whether we are still ourselves.
func SelfStartTime() uint64 {
	start, _ := ProcStartTimeOf(os.Getpid())
	return start
}

// ProcRealUID reads the real uid from /proc/<pid>/status.
func ProcRealUID(pid int) (int, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			break
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0, fmt.Errorf("uid of %d unreadable: %w", pid, err)
		}
		return uid, nil
	}
	return 0, fmt.Errorf("/proc/%d/status has no Uid line", pid)
}

// AliveWithStarttime reports whether the process in that slot is still the one
// that started at that tick count.
func AliveWithStarttime(pid int, starttime uint64) bool {
	current, err := ProcStartTimeOf(pid)
	if err != nil {
		return false
	}
	return current == starttime
}

// SocketIsLive reports whether something is listening on the control socket.
//
// Probing by dialing costs nothing and interferes with nothing: the engine has
// already accepted its one connection, so a probe joins the listen backlog,
// sends no bytes, and closes. What it proves is exactly what matters — that
// the listener still exists. A vanished file or a refused dial means the UI's
// listener is gone, whatever happened to the process holding it.
func SocketIsLive(path string) bool {
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

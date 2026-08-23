//go:build linux

package helper

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Recovery is deliberately narrow. A previous run that died badly can leave two
// kinds of mess: a root-owned core still running, and a TUN interface with its
// routes still installed. Both are cleaned here — but only when they are
// provably this app's own, because a cleanup that deletes "anything shaped
// like ours" deletes other people's tunnels with them.

// LeftoverCorePIDs lists root processes whose executable is exactly the
// installed core.
//
// The /proc/<pid>/exe link is the proof, not the process name: anything can
// call itself mihomo in a process list, while exe names what would actually
// run. Re-checked immediately before signalling so a recycled PID cannot turn
// this into killing someone else's program.
func LeftoverCorePIDs(corePath string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		exe, err := os.Readlink("/proc/" + entry.Name() + "/exe")
		if err != nil || exe != corePath {
			continue
		}
		uid, err := ProcRealUID(pid)
		if err != nil || uid != 0 {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// TerminateAll asks every process to leave at once, waits out the grace
// period while they do, then makes the ones still standing. The waiting is one
// poll loop against the deadline — not a nap per process, which would give the
// first PID the whole grace and the last one none of it.
func TerminateAll(pids []int, grace time.Duration) {
	living := make([]int, 0, len(pids))
	for _, pid := range pids {
		if err := unix.Kill(pid, syscall.SIGTERM); err != nil {
			continue // already gone, or not ours to signal
		}
		living = append(living, pid)
	}
	if len(living) == 0 {
		return
	}

	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		survivors := living[:0]
		for _, pid := range living {
			if unix.Kill(pid, 0) == nil {
				survivors = append(survivors, pid)
			}
		}
		if len(survivors) == 0 {
			return
		}
		living = survivors
		time.Sleep(100 * time.Millisecond)
	}
	for _, pid := range living {
		_ = unix.Kill(pid, syscall.SIGKILL)
	}
}

// RemoveStaleTun deletes one leftover tunnel interface — and only if it is
// demonstrably a kernel TUN/TAP device created by tuntap.
//
// The proof is /sys/class/net/<name>/tun_flags, an attribute only tuntap
// devices have. An interface somebody named like ours for their own reasons,
// or any ordinary NIC, lacks it and is never touched; deleting by name alone
// would be deleting whatever happens to share a label.
func RemoveStaleTun(name string) error {
	tunFlags := "/sys/class/net/" + name + "/tun_flags"
	if _, err := os.Stat(tunFlags); err != nil {
		if os.IsNotExist(err) {
			// Absent device, or present-but-not-tuntap: nothing of ours to
			// clean up either way.
			return nil
		}
		return err
	}
	indexBytes, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return err
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(indexBytes)))
	if err != nil {
		return fmt.Errorf("ifindex of %s unreadable: %w", name, err)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	deadline := unix.NsecToTimeval(int64(2 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &deadline)

	request := BuildDeleteLinkRequest(index, 1)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	reply := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, reply, 0)
	if err != nil {
		return err
	}
	ackErr := NetlinkAckError(reply[:n])
	// ENODEV after we proved existence means it vanished under us: fine.
	var errno *Errno
	if ackErrAs(ackErr, &errno) && errno.Code == int32(unix.ENODEV) {
		return nil
	}
	return ackErr
}

func ackErrAs(err error, target **Errno) bool {
	e, ok := err.(*Errno)
	if ok {
		*target = e
	}
	return ok
}

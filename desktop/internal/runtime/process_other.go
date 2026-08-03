//go:build !windows

package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"syscall"
)

func hideConsoleWindow(_ *exec.Cmd) {}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	if goruntime.GOOS == "linux" {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			return false
		}
		if err == nil {
			stat := string(raw)
			if idx := strings.LastIndex(stat, ") "); idx >= 0 && len(stat) > idx+2 {
				fields := strings.Fields(stat[idx+2:])
				if len(fields) > 0 && fields[0] == "Z" {
					return false
				}
			}
		}
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

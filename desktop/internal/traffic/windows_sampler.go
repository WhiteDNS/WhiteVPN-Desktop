//go:build windows

package traffic

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type WindowsProcessIOSampler struct{}

type windowsIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

var getProcessIOCountersProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIoCounters")

func (WindowsProcessIOSampler) Sample(ctx context.Context, pid int) (Counters, error) {
	if pid <= 0 {
		return Counters{}, fmt.Errorf("invalid process id: %d", pid)
	}
	if err := ctx.Err(); err != nil {
		return Counters{}, err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Counters{}, fmt.Errorf("Windows traffic monitor unavailable: %w", err)
	}
	defer windows.CloseHandle(handle)

	var counters windowsIOCounters
	ok, _, callErr := getProcessIOCountersProc.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)))
	if ok == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return Counters{}, fmt.Errorf("Windows traffic monitor unavailable: %w", callErr)
		}
		return Counters{}, fmt.Errorf("Windows traffic monitor unavailable")
	}
	return Counters{
		RXBytes: int64(clampWindowsCounter(counters.ReadTransferCount)),
		TXBytes: int64(clampWindowsCounter(counters.WriteTransferCount)),
	}, nil
}

func clampWindowsCounter(value uint64) uint64 {
	const maxInt64 = uint64(1<<63 - 1)
	if value > maxInt64 {
		return maxInt64
	}
	return value
}

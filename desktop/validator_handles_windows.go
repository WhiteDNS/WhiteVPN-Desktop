//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var getProcessHandleCountProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func validatorProcessHandleCount() int {
	var count uint32
	ok, _, _ := getProcessHandleCountProc.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&count)),
	)
	if ok == 0 {
		return 0
	}
	return int(count)
}

//go:build darwin

package macossvc

// #cgo LDFLAGS: -framework Foundation -lobjc
// #include <stdlib.h>
// #include "bridge.h"
import "C"

import (
	"fmt"
	"unsafe"
)

func available() bool { return C.wv_available() == 1 }

// goString frees the C string it converts, so no bridge call can leak.
func goString(c *C.char) string {
	if c == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(c))
	return C.GoString(c)
}

func (s Service) status() (int, error) {
	if !available() {
		return 0, ErrUnsupportedPlatform
	}
	var out, errOut *C.char
	code := C.wv_sm_status(C.CString(s.plistName), &out, &errOut)
	if code != 0 {
		return 0, fmt.Errorf("macossvc: %s", goString(errOut))
	}
	switch text := goString(out); text {
	case "notRegistered":
		return 1, nil
	case "enabled":
		return 2, nil
	case "requiresApproval":
		return 3, nil
	case "notFound":
		return 4, nil
	default:
		return 0, fmt.Errorf("macossvc: unknown registration status %q", text)
	}
}

func (s Service) register() error {
	var errOut *C.char
	if C.wv_sm_register(C.CString(s.plistName), &errOut) != 0 {
		return fmt.Errorf("macossvc: %s", goString(errOut))
	}
	return nil
}

func (s Service) unregister() error {
	var errOut *C.char
	if C.wv_sm_unregister(C.CString(s.plistName), &errOut) != 0 {
		return fmt.Errorf("macossvc: %s", goString(errOut))
	}
	return nil
}

func (s Service) request(op string, timeoutMs int) (string, error) {
	if !available() {
		return "", ErrUnsupportedPlatform
	}
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	var errOut *C.char
	serviceName := C.CString(machServiceName)
	method := C.CString(op)
	reply := C.wv_xpc_call(serviceName, method, nil,
		C.double(float64(timeoutMs)/1000.0), &errOut)
	C.free(unsafe.Pointer(serviceName))
	C.free(unsafe.Pointer(method))
	if errOut != nil {
		return "", fmt.Errorf("macossvc: %s", goString(errOut))
	}
	return goString(reply), nil
}

// machServiceName is the launchd label the daemon advertises. It lives here
// rather than in service.go because only the platform that launches the daemon
// should decide its name.
const machServiceName = "com.whitevpn.vpn.daemon"

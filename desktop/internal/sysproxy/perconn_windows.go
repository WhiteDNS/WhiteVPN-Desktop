//go:build windows

package sysproxy

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The connection settings WinINET actually reads.
//
// `ProxyEnable` and `ProxyServer` under Internet Settings are a compatibility
// shim. The real configuration is a binary blob —
// `Connections\DefaultConnectionSettings` — and when the two disagree the blob
// wins. Writing only the shim is why the app could set the proxy, read it back,
// verify it, show a badge, and have Windows go on browsing directly: the blob
// still said flags=1, PROXY_TYPE_DIRECT.
//
// This is the documented way to change it. It updates the blob and the shim
// together, so the two cannot drift, and it does the same thing the Internet
// Options dialog does.
const (
	internetOptionPerConnectionOption = 75

	perConnFlags       = 1
	perConnProxyServer = 2
	perConnProxyBypass = 3

	proxyTypeDirect = 0x00000001
	proxyTypeProxy  = 0x00000002
)

// perConnOption is INTERNET_PER_CONN_OPTION. The union is pointer-sized, and Go
// pads after the uint32 exactly as C does.
type perConnOption struct {
	option uint32
	value  uintptr
}

// perConnOptionList is INTERNET_PER_CONN_OPTION_LIST.
type perConnOptionList struct {
	size       uint32
	connection *uint16
	count      uint32
	err        uint32
	options    uintptr
}

var procInternetQueryOption = wininet.NewProc("InternetQueryOptionW")

// applyPerConnection sets the proxy through WinINET rather than around it.
func applyPerConnection(state State) error {
	// Whatever else was configured is kept. Auto-detect and a configuration
	// script live in these same flags, and this app has no business turning
	// either off on the way past.
	flags := state.Flags | proxyTypeDirect
	if state.Enabled {
		// Direct stays set alongside Proxy: that is the combination the
		// Internet Options dialog writes for "use a proxy server", and it is
		// what keeps bypassed addresses reaching the network at all.
		flags |= proxyTypeProxy
	} else {
		flags &^= proxyTypeProxy
	}

	server, err := windows.UTF16PtrFromString(state.Server)
	if err != nil {
		return fmt.Errorf("sysproxy: proxy address: %w", err)
	}
	bypass, err := windows.UTF16PtrFromString(state.Override)
	if err != nil {
		return fmt.Errorf("sysproxy: bypass list: %w", err)
	}

	options := []perConnOption{
		{option: perConnFlags, value: uintptr(flags)},
		{option: perConnProxyServer, value: uintptr(unsafe.Pointer(server))},
		{option: perConnProxyBypass, value: uintptr(unsafe.Pointer(bypass))},
	}
	list := perConnOptionList{
		size: uint32(unsafe.Sizeof(perConnOptionList{})),
		// NULL means the default connection — the LAN entry, which is what a
		// machine without dial-up or a VPN adapter uses, and what a browser
		// reads.
		connection: nil,
		count:      uint32(len(options)),
		options:    uintptr(unsafe.Pointer(&options[0])),
	}

	result, _, callErr := procInternetSetOption.Call(
		0,
		internetOptionPerConnectionOption,
		uintptr(unsafe.Pointer(&list)),
		uintptr(list.size),
	)
	// The strings and the option array must outlive the call; nothing above
	// keeps a Go reference to them once their addresses are in the struct.
	runtime.KeepAlive(server)
	runtime.KeepAlive(bypass)
	runtime.KeepAlive(options)
	if result == 0 {
		return fmt.Errorf("sysproxy: the system refused the connection settings: %w", callErr)
	}
	return nil
}

// perConnectionProxyEnabled asks WinINET whether the default connection is set
// to use a proxy.
//
// Only the flags, which are a plain DWORD: reading the strings back means
// WinINET allocating them and this code freeing them, and the flags alone are
// what the shim cannot be trusted about.
func perConnectionProxyEnabled() (bool, error) {
	flags, err := perConnectionFlags()
	if err != nil {
		return false, err
	}
	return flags&proxyTypeProxy != 0, nil
}

// perConnectionFlags reads the flags verbatim.
func perConnectionFlags() (uint32, error) {
	options := []perConnOption{{option: perConnFlags}}
	list := perConnOptionList{
		size:    uint32(unsafe.Sizeof(perConnOptionList{})),
		count:   uint32(len(options)),
		options: uintptr(unsafe.Pointer(&options[0])),
	}
	size := list.size

	result, _, callErr := procInternetQueryOption.Call(
		0,
		internetOptionPerConnectionOption,
		uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Pointer(&size)),
	)
	runtime.KeepAlive(options)
	if result == 0 {
		return 0, fmt.Errorf("sysproxy: could not read the connection settings: %w", callErr)
	}
	return uint32(options[0].value), nil
}

//go:build !linux

package main

// trayIconIsDisplayed reports whether some host on this desktop will draw the
// icon.
//
// Windows and macOS both have one notification area, always present, owned by
// the shell. An icon registered there is an icon shown, so the library having
// started is the whole answer and there is nothing further to ask.
//
// Only Linux can register an icon that nothing displays, which is why the real
// check lives in tray_linux.go.
func trayIconIsDisplayed() bool { return true }

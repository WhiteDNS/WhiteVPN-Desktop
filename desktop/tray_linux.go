//go:build linux

package main

// Whether this desktop will actually show a tray icon.
//
// Closing the window hides the app rather than quitting it, on the reasoning
// that closing a VPN's window means "get out of my way", not "stop protecting
// my traffic". That trade only holds while there is an icon to come back from,
// so hideInsteadOfClosing asks the tray whether it is running first.
//
// On Linux that answer was always yes, and it was worthless. systray's
// nativeStart calls the ready callback before it connects to D-Bus at all, and
// a failure to register with the watcher afterwards only writes a line to the
// log — so onTrayReady runs, markReady(true) happens, and the app believes it
// has an icon whether or not anything is displaying one.
//
// GNOME ships no StatusNotifierHost without an extension, which is the common
// case rather than the exotic one. A user there closed the window, the app
// hid itself, no icon appeared, and there was nothing left to click: exactly
// the state the guard exists to prevent, reached through the guard.
//
// So the question is asked of the session bus instead of the library: is anyone
// claiming to host status icons? A name with no owner means no host, which means
// closing the window has to mean quitting.

import (
	"github.com/godbus/dbus/v5"
)

// statusNotifierWatcher is the bus name a tray host claims. KDE's name, used by
// every implementation including GNOME's AppIndicator extensions.
const statusNotifierWatcher = "org.kde.StatusNotifierWatcher"

// trayIconIsDisplayed reports whether some host on this desktop will draw the
// icon.
//
// Failing closed: anything unclear here is answered "no", because being wrong
// that way costs a window that quits when closed, and being wrong the other way
// costs an app the user cannot reach at all.
func trayIconIsDisplayed() bool {
	conn, err := dbus.SessionBus()
	if err != nil {
		return false
	}

	var owner string
	err = conn.BusObject().Call(
		"org.freedesktop.DBus.GetNameOwner", 0, statusNotifierWatcher,
	).Store(&owner)
	if err != nil {
		// NameHasNoOwner, or no bus to ask. Either way nothing is hosting icons.
		return false
	}
	return owner != ""
}

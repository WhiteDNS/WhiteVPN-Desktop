package main

import (
	"context"
	_ "embed"
	"runtime"
	"strings"
	"sync"

	"fyne.io/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"whitevpn-desktop/internal/model"
)

// The tray icon, and what makes closing the window not the same as quitting.
//
// A VPN is not a document: closing its window means "get out of my way", not
// "stop protecting my traffic". So the window hides and the app keeps running —
// but only once there is a tray icon to bring it back from. If the tray never
// came up, closing the window quits, because an app with no window and no icon
// is one the user can only end through Task Manager.

//go:embed build/windows/icon.ico
var trayIconICO []byte

//go:embed build/appicon.png
var trayIconPNG []byte

type trayState struct {
	mu      sync.Mutex
	ready   bool
	refresh chan struct{}

	status  *systray.MenuItem
	toggle  *systray.MenuItem
	show    *systray.MenuItem
	quit    *systray.MenuItem
	stopped bool
}

// running reports whether there is an icon to restore the window from.
func (t *trayState) running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ready && !t.stopped
}

func (t *trayState) markReady(ready bool) {
	t.mu.Lock()
	t.ready = ready
	t.mu.Unlock()
}

// startTray brings the icon up. It returns immediately; the icon appears when
// the system is ready for it.
func (a *App) startTray() {
	a.tray.refresh = make(chan struct{}, 1)
	if runtime.GOOS == "darwin" {
		systray.Register(a.onTrayReady, a.onTrayExit)
		return
	}
	go func() {
		// The icon's window and the loop that pumps its messages have to stay on
		// one OS thread. Windows delivers a window's messages only to the thread
		// that created it, and GetMessage reads the calling thread's queue — so a
		// goroutine the scheduler moves between threads creates the window on one
		// and then listens on another, where nothing ever arrives.
		//
		// systray locks the thread in its own init(), which covers a Run() on the
		// main goroutine. Starting one with `go` steps outside that: the icon
		// still appears, because it is created once, and then every click,
		// every menu open and Quit itself go into a queue nobody reads. What the
		// user sees is an icon that does nothing and an app that can only be
		// ended from Task Manager.
		//
		// Not unlocked afterwards: the goroutine only returns once the tray has
		// quit, and letting the thread die with it is better than handing a
		// thread that owned a window back for general use.
		runtime.LockOSThread()
		systray.Run(a.onTrayReady, a.onTrayExit)
	}()
}

func (a *App) onTrayReady() {
	systray.SetIcon(trayIcon())
	systray.SetTitle(trayAppName)
	systray.SetTooltip(trayAppName)

	words := a.trayStrings()
	a.tray.status = systray.AddMenuItem(words.disconnected, "")
	a.tray.status.Disable()
	systray.AddSeparator()
	a.tray.toggle = systray.AddMenuItem(words.connect, "")
	a.tray.show = systray.AddMenuItem(words.show, "")
	systray.AddSeparator()
	a.tray.quit = systray.AddMenuItem(words.quit, "")

	// A left click is the shortest way back to the window; the menu stays on the
	// right button, where the platform puts it.
	systray.SetOnTapped(func() { a.showWindow() })

	a.tray.markReady(true)
	a.refreshTray()

	for {
		select {
		case <-a.tray.toggle.ClickedCh:
			go a.toggleFromTray()
		case <-a.tray.show.ClickedCh:
			a.showWindow()
		case <-a.tray.quit.ClickedCh:
			a.quitFromTray()
			return
		case <-a.tray.refresh:
			a.refreshTray()
		}
	}
}

func (a *App) onTrayExit() {
	a.tray.mu.Lock()
	a.tray.stopped = true
	a.tray.mu.Unlock()
}

// notifyTray asks the icon to re-read the runtime state. It never blocks: the
// tray is a display, and a display that can hold up a connection is worse than
// one that misses a frame.
func (a *App) notifyTray() {
	if a.tray.refresh == nil {
		return
	}
	select {
	case a.tray.refresh <- struct{}{}:
	default:
	}
}

func (a *App) refreshTray() {
	if !a.tray.running() {
		return
	}
	state := a.GetAppState()
	words := a.trayStrings()

	label := words.disconnected
	toggle := words.connect
	switch state.Runtime.Status {
	case model.RuntimeConnected:
		label = words.connected
		toggle = words.disconnect
		if country := state.Runtime.ExitCountryCode; country != "" {
			label = words.connected + " — " + country
		}
	case model.RuntimeConnecting:
		label, toggle = words.connecting, words.disconnect
	case model.RuntimeStopping:
		label, toggle = words.stopping, words.disconnect
	case model.RuntimeFailed:
		label, toggle = words.failed, words.retry
	}

	a.tray.status.SetTitle(label)
	a.tray.toggle.SetTitle(toggle)
	a.tray.show.SetTitle(words.show)
	a.tray.quit.SetTitle(words.quit)
	systray.SetTooltip(trayAppName + " — " + label)

	// Nothing to toggle while stopping, exactly as the button on the page.
	if state.Runtime.Status == model.RuntimeStopping {
		a.tray.toggle.Disable()
	} else {
		a.tray.toggle.Enable()
	}
}

func (a *App) toggleFromTray() {
	switch a.GetAppState().Runtime.Status {
	case model.RuntimeConnected, model.RuntimeConnecting:
		_, _ = a.StopConnection()
	default:
		_, _ = a.StartWhiteDNSVPNConnection()
	}
}

func (a *App) showWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowShow(a.ctx)
	wailsruntime.WindowUnminimise(a.ctx)
}

func (a *App) quitFromTray() {
	systray.Quit()
	if a.ctx != nil {
		wailsruntime.Quit(a.ctx)
		return
	}
	a.shutdown(context.Background())
}

// hideInsteadOfClosing is Wails' OnBeforeClose. Returning true keeps the window.
func (a *App) hideInsteadOfClosing(ctx context.Context) bool {
	// No icon to come back from: closing the window has to mean quitting, or the
	// app becomes something only a process manager can end.
	//
	// Both halves are needed. running() says the library started; it does not say
	// anything is drawing the result, and on Linux it always says yes — systray
	// fires its ready callback before it has so much as opened the session bus.
	// A GNOME user without an AppIndicator extension closed the window, watched
	// the app vanish with no icon anywhere, and had to kill it from htop.
	if !a.tray.running() || !trayIconIsDisplayed() {
		return false
	}
	wailsruntime.WindowHide(ctx)
	return true
}

const trayAppName = "WhiteVPN"

type trayWords struct {
	connected    string
	connecting   string
	stopping     string
	disconnected string
	failed       string
	connect      string
	disconnect   string
	retry        string
	show         string
	quit         string
}

// The tray is drawn by the system, not by the page, so its words cannot come
// from the interface's own translations. These are the same phrases, kept in
// step with `frontend/src/i18n.ts` by hand — there are ten of them.
func (a *App) trayStrings() trayWords {
	english := trayWords{
		connected:    "Connected",
		connecting:   "Connecting…",
		stopping:     "Disconnecting…",
		disconnected: "Disconnected",
		failed:       "Failed",
		connect:      "Connect",
		disconnect:   "Disconnect",
		retry:        "Retry",
		show:         "Open WhiteVPN",
		quit:         "Quit",
	}
	if !strings.EqualFold(a.GetAppState().WhiteVPN.Language, "fa") {
		return english
	}
	return trayWords{
		connected:    "متصل",
		connecting:   "در حال اتصال…",
		stopping:     "در حال قطع اتصال…",
		disconnected: "قطع",
		failed:       "ناموفق",
		connect:      "اتصال",
		disconnect:   "قطع اتصال",
		retry:        "تلاش دوباره",
		show:         "باز کردن وایت‌وی‌پی‌ان",
		quit:         "خروج",
	}
}

func trayIcon() []byte {
	if runtime.GOOS == "windows" {
		return trayIconICO
	}
	return trayIconPNG
}

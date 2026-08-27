package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

// The engine travels inside the app, so an install is one file. cores/ holds
// only what this app runs now: mihomo, and on Windows the tunnel driver it
// needs to create an adapter.
//
//go:embed all:cores
var coreAssets embed.FS

//go:embed filtered_ipv4.csv
var defaultIPv4RangeAssets embed.FS

func main() {
	app, err := NewApp()
	if err != nil {
		println("Startup error:", err.Error())
		return
	}

	err = wails.Run(&options.App{
		Title:     "WhiteVPN Desktop",
		Width:     1280,
		Height:    820,
		MinWidth:  860,
		MinHeight: 620,
		// Closing is decided at the time, by whether there is a tray icon to
		// bring the window back from - see hideInsteadOfClosing.
		HideWindowOnClose: false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 252, G: 252, B: 252, A: 1},
		// One window, however many times the icon is clicked.
		//
		// Without this every launch started another copy: another taskbar
		// button, another tray icon, another engine ready to fight the first
		// one for the proxy port and the tunnel adapter. Clicking a desktop
		// shortcut twice is not a thing to be punished for, and on Windows a
		// running app with its window hidden to the tray looks exactly like one
		// that is not running — so the second launch is the expected move, not
		// a mistake.
		//
		// The lock's answer is to show the window that already exists, which is
		// what the person clicking wanted in the first place. The second
		// process then exits on its own.
		SingleInstanceLock: &options.SingleInstanceLock{
			// Not the app name: this is the identity of a running instance, and
			// two builds of different versions are still the same app to a
			// user. A fixed string keeps that true across upgrades.
			UniqueId:               "whitevpn-desktop-single-instance",
			OnSecondInstanceLaunch: app.onSecondInstanceLaunch,
		},
		OnStartup:     app.startup,
		OnShutdown:    app.shutdown,
		OnBeforeClose: app.hideInsteadOfClosing,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}

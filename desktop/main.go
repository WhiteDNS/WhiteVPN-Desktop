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
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.hideInsteadOfClosing,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}

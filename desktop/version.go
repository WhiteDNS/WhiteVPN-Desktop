package main

// appVersion is set at link time by the Makefile:
//
//	-ldflags "-X main.appVersion=$(APP_VERSION)"
//
// It exists because the version used to be typed into the interface by hand,
// so releasing 1.0.1 shipped an app that said 1.0.0 in its own sidebar. A
// number a human has to remember to change in two places is a number that will
// be wrong.
//
// A build that goes through the Makefile carries the real version. A plain
// `wails build` or `go run` carries "dev", which is honest — it is a
// development build, and saying so beats claiming a release number nobody cut.
var appVersion = "dev"

// GetAppVersion is what the interface shows beside the app's name.
func (a *App) GetAppVersion() string {
	return appVersion
}

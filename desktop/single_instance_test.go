package main

import (
	"testing"

	"github.com/wailsapp/wails/v2/pkg/options"
	"whitevpn-desktop/internal/model"
)

// A second launch can arrive before the first has finished starting, which is
// exactly what happens when somebody double-clicks the shortcut. The handler
// runs on the instance that is already going, and at that moment its window may
// not exist yet — so it has to do nothing rather than take the whole app down
// with it.
func TestASecondLaunchBeforeTheWindowExistsIsHarmless(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	if app.ctx != nil {
		t.Fatal("this test is only meaningful before startup has run")
	}
	app.onSecondInstanceLaunch(options.SecondInstanceData{})
}

// The arguments a second launch carried are ignored on purpose: this app
// defines none that mean anything, and acting on one would be inventing
// behaviour at the entry point hardest to see from the interface.
func TestASecondLaunchIgnoresWhateverItWasGiven(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.onSecondInstanceLaunch(options.SecondInstanceData{
		Args:             []string{"--connect", "/etc/passwd", "whitevpn://join"},
		WorkingDirectory: `C:\somewhere\else`,
	})
}

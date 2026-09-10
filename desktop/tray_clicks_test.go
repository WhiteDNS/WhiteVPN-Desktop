package main

import (
	"testing"
	"time"

	"whitevpn-desktop/internal/model"
)

// The loop has to survive being moved off the ready callback.
//
// It was moved because systray only releases the WaitGroup that guards its
// D-Bus GetLayout when the ready callback returns, and the callback used to end
// in this loop — so on Linux the menu never arrived and the icon appeared to do
// nothing. Nothing about that is visible from here; what is testable is that
// the loop still serves what it served before from wherever it runs.
func TestTheTrayClickLoopStillServesRefreshes(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.tray.refresh = make(chan struct{}, 1)
	// Not ready, so refreshTray returns before touching any menu item — this is
	// about the loop being alive, not about what it draws.
	toggle := make(chan struct{})
	show := make(chan struct{})
	quit := make(chan struct{})

	done := make(chan struct{})
	go func() {
		app.watchTrayClicks(toggle, show, quit)
		close(done)
	}()

	// Show is the click the issue was about, and with no window context it is a
	// no-op the loop must survive rather than a panic.
	show <- struct{}{}
	app.notifyTray()

	// Still serving after both: a loop that had exited would block here.
	select {
	case show <- struct{}{}:
	case <-time.After(2 * time.Second):
		t.Fatal("the click loop stopped serving")
	}

	select {
	case <-done:
		t.Fatal("the loop returned before it was asked to quit")
	default:
	}
}

// notifyTray must never block, because it is called from the connect path and a
// display that can hold up a connection is worse than one that misses a frame.
func TestNotifyingTheTrayNeverBlocks(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.tray.refresh = make(chan struct{}, 1)

	done := make(chan struct{})
	go func() {
		// Nothing is reading, and the buffer holds one.
		for i := 0; i < 10; i++ {
			app.notifyTray()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notifyTray blocked with nothing reading the channel")
	}
}

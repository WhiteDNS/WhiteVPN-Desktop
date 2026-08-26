package main

import (
	"bytes"
	"image/png"
	"runtime"
	"testing"

	"whitevpn-desktop/internal/model"
)

// The point of the feature: the states have to be told apart at a glance, and
// the pair that matters most is connected against disconnected. The first
// attempt left the connected icon untinted, which made those two black and grey
// — the weakest distinction in the set, and the one it exists to make.
func TestEveryTrayStateLooksDifferentFromEveryOther(t *testing.T) {
	states := []string{
		model.RuntimeConnected,
		model.RuntimeConnecting,
		model.RuntimeFailed,
		model.RuntimeDisconnected,
	}
	seen := map[string]string{}
	for _, state := range states {
		icon := trayIconFor(state)
		if len(icon) == 0 {
			t.Fatalf("%s has no icon at all", state)
		}
		if previous, ok := seen[string(icon)]; ok {
			t.Fatalf("%s and %s are the same image, so the tray cannot tell them apart", state, previous)
		}
		seen[string(icon)] = state
	}
}

// A status nothing was drawn for still has to produce an icon. Returning
// nothing would leave the tray blank, and a blank tray is an app that cannot be
// reached once its window is closed.
func TestAnUnknownStatusStillGetsAnIcon(t *testing.T) {
	if len(trayIconFor("something-nobody-has-written-yet")) == 0 {
		t.Fatal("an unrecognised status left the tray with no icon")
	}
	if len(trayIconFor("")) == 0 {
		t.Fatal("an empty status left the tray with no icon")
	}
}

// Windows will not draw a PNG handed to it as an icon, so the container has to
// be right. The rest of the world takes the PNG as it is.
func TestTheIconIsInTheFormatThisPlatformDraws(t *testing.T) {
	icon := trayIconFor(model.RuntimeConnected)
	payload := icon
	if isWindows() {
		if len(icon) < 22 {
			t.Fatal("an ICO cannot be shorter than its own header")
		}
		// ICONDIR: reserved 0, type 1, one image.
		if want := []byte{0, 0, 1, 0, 1, 0}; !bytes.Equal(icon[:6], want) {
			t.Fatalf("the ICO header is wrong: got %v, want %v", icon[:6], want)
		}
		if icon[0+6] != traySize || icon[1+6] != traySize {
			t.Fatalf("the ICO declares %dx%d, but the image is %d", icon[6], icon[7], traySize)
		}
		payload = icon[22:]
	}
	image, err := png.Decode(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("the icon does not contain a readable PNG: %v", err)
	}
	if image.Bounds().Dx() != traySize || image.Bounds().Dy() != traySize {
		t.Fatalf("the icon is %v, want %dx%d", image.Bounds().Size(), traySize, traySize)
	}
}

// Deriving the icons is the reason they are not four more embedded files, so it
// has to actually be cheaper than the thing it replaced.
func TestADerivedIconIsSmallerThanTheOneItReplaces(t *testing.T) {
	derived := len(trayIconFor(model.RuntimeConnected))
	if derived >= len(trayIcon()) {
		t.Fatalf("the derived icon is %d bytes against the shipped %d — deriving is buying nothing", derived, len(trayIcon()))
	}
}

func isWindows() bool { return runtime.GOOS == "windows" }

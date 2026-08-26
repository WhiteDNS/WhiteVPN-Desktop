package main

// Making the tray icon say whether traffic is being carried.
//
// Asked for by a user: knowing whether the connection is up meant opening the
// window, when the icon is already on screen and could simply say so. The menu
// and the tooltip have carried the status all along, but both need a click or a
// hover — the colour needs neither, which is the whole point of an icon.
//
// The variants are derived from the one embedded logo at runtime rather than
// shipped as four more files. The source is a 1024px PNG that already costs
// 1.6 MB in the binary; four of those would be six, to say one of four things.
// Deriving them also means the icon has one source of truth, so redrawing the
// logo does not leave three stale copies behind.
//
// Each state drains the colour out of the logo and pulls it towards one hue —
// green, amber, red, grey. Colour rather than a change of shape, because a
// shape has to be recognised and a colour only has to be seen, and at sixteen
// pixels on a busy taskbar that is the whole difference.

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"runtime"
	"sync"

	"whitevpn-desktop/internal/model"
)

// traySize is what the derived icons are scaled to.
//
// Trays draw at 16 or 24 points and ask for more on a HiDPI screen. 64 covers
// that with room to spare and is a sixteenth of the source in each direction,
// which makes the box filter below an exact average rather than a resampling.
const traySize = 64

// trayTint is how a state colours the icon: a colour to pull it towards, and
// how far. Zero strength leaves it alone.
type trayTint struct {
	colour   color.RGBA
	strength float64
}

// The palette.
//
// Connected is tinted rather than left as the logo, which was the first attempt
// and the wrong one. The logo is dark and nearly monochrome, so "connected" and
// "disconnected" came out as black and grey — the weakest distinction in the
// set, and the one the whole feature exists to make. On a dark taskbar the
// untinted version all but disappears. Green is what every other client on the
// platform uses for this, and it survives being sixteen pixels wide.
var trayTints = map[string]trayTint{
	model.RuntimeConnected:    {colour: color.RGBA{R: 0x3F, G: 0xB9, B: 0x63, A: 0xFF}, strength: 0.8},
	model.RuntimeConnecting:   {colour: color.RGBA{R: 0xE8, G: 0xA3, B: 0x3D, A: 0xFF}, strength: 0.75},
	model.RuntimeStopping:     {colour: color.RGBA{R: 0xE8, G: 0xA3, B: 0x3D, A: 0xFF}, strength: 0.75},
	model.RuntimeFailed:       {colour: color.RGBA{R: 0xD9, G: 0x4B, B: 0x4B, A: 0xFF}, strength: 0.8},
	model.RuntimeDisconnected: {colour: color.RGBA{R: 0x8A, G: 0x8A, B: 0x92, A: 0xFF}, strength: 0.85},
}

var (
	trayIconsOnce sync.Once
	trayIcons     map[string][]byte
	trayIconBase  []byte
)

// trayIconFor returns the icon bytes for a runtime status.
//
// It never fails: if the logo cannot be decoded — which would mean the embedded
// asset is broken and the build is wrong — every state gets the icon that
// shipped, and the tray looks exactly as it did before this existed. An icon
// that does not change colour is a small loss; no icon at all is the app
// becoming unreachable once its window is closed.
func trayIconFor(status string) []byte {
	trayIconsOnce.Do(buildTrayIcons)
	if icon, ok := trayIcons[status]; ok {
		return icon
	}
	return trayIconBase
}

func buildTrayIcons() {
	trayIconBase = trayIcon()
	trayIcons = map[string][]byte{}

	source, err := png.Decode(bytes.NewReader(trayIconPNG))
	if err != nil {
		return
	}
	scaled := downscale(source, traySize)
	for status, tint := range trayTints {
		encoded, err := encodeTrayIcon(applyTint(scaled, tint))
		if err != nil {
			continue
		}
		trayIcons[status] = encoded
	}
}

// downscale averages the source down to a square of the given size.
//
// A box filter rather than nearest neighbour: dropping fifteen pixels in
// sixteen off a logo with thin strokes is how an icon comes out looking like it
// was drawn with a broken pen.
func downscale(source image.Image, size int) *image.NRGBA {
	bounds := source.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			x0 := bounds.Min.X + x*bounds.Dx()/size
			x1 := bounds.Min.X + (x+1)*bounds.Dx()/size
			y0 := bounds.Min.Y + y*bounds.Dy()/size
			y1 := bounds.Min.Y + (y+1)*bounds.Dy()/size

			var r, g, b, a, n uint64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					// Alpha-weighted, so a transparent pixel's colour — which is
					// arbitrary — does not wash into its opaque neighbours and
					// leave a halo around the logo.
					sr, sg, sb, sa := source.At(sx, sy).RGBA()
					r += uint64(sr)
					g += uint64(sg)
					b += uint64(sb)
					a += uint64(sa)
					n++
				}
			}
			if n == 0 {
				continue
			}
			alpha := a / n
			pixel := color.NRGBA{A: uint8(alpha >> 8)}
			if alpha > 0 {
				// Back out of premultiplied form, which is what RGBA() returns.
				pixel.R = uint8(min64(r/n*0xFFFF/alpha, 0xFFFF) >> 8)
				pixel.G = uint8(min64(g/n*0xFFFF/alpha, 0xFFFF) >> 8)
				pixel.B = uint8(min64(b/n*0xFFFF/alpha, 0xFFFF) >> 8)
			}
			out.SetNRGBA(x, y, pixel)
		}
	}
	return out
}

// applyTint drains the colour out of an image and pulls it towards one hue.
//
// Through luminance rather than by multiplying the original channels: the logo
// is not one colour, and multiplying leaves its darker parts almost black while
// its lighter parts take the tint, which reads as a smudge rather than a state.
func applyTint(source *image.NRGBA, tint trayTint) *image.NRGBA {
	if tint.strength <= 0 {
		return source
	}
	out := image.NewNRGBA(source.Bounds())
	copy(out.Pix, source.Pix)
	for i := 0; i < len(out.Pix); i += 4 {
		if out.Pix[i+3] == 0 {
			continue
		}
		luma := 0.2126*float64(out.Pix[i]) + 0.7152*float64(out.Pix[i+1]) + 0.0722*float64(out.Pix[i+2])
		// Held off pure black so a dark logo still shows its tint rather than
		// turning into a silhouette.
		lit := 0.35 + 0.65*(luma/255)
		out.Pix[i] = blend(out.Pix[i], uint8(float64(tint.colour.R)*lit), tint.strength)
		out.Pix[i+1] = blend(out.Pix[i+1], uint8(float64(tint.colour.G)*lit), tint.strength)
		out.Pix[i+2] = blend(out.Pix[i+2], uint8(float64(tint.colour.B)*lit), tint.strength)
	}
	return out
}

func blend(from, to uint8, strength float64) uint8 {
	return uint8(float64(from)*(1-strength) + float64(to)*strength)
}

func min64(value, limit uint64) uint64 {
	if value > limit {
		return limit
	}
	return value
}

// encodeTrayIcon writes the image in the format this platform's tray wants.
//
// Windows wants an ICO, which since Vista may hold a PNG directly rather than
// the old bitmap-with-a-mask — so the container is twenty-two bytes of header
// around the same PNG everything else gets.
func encodeTrayIcon(img image.Image) ([]byte, error) {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, img); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		return encoded.Bytes(), nil
	}

	size := img.Bounds().Dx()
	if size >= 256 {
		// The field is one byte and 0 is how the format spells 256.
		size = 0
	}
	var ico bytes.Buffer
	// ICONDIR: reserved, type 1 (icon), one image.
	_ = binary.Write(&ico, binary.LittleEndian, [3]uint16{0, 1, 1})
	// ICONDIRENTRY: width, height, palette size, reserved.
	ico.Write([]byte{byte(size), byte(size), 0, 0})
	_ = binary.Write(&ico, binary.LittleEndian, uint16(1))  // colour planes
	_ = binary.Write(&ico, binary.LittleEndian, uint16(32)) // bits per pixel
	_ = binary.Write(&ico, binary.LittleEndian, uint32(encoded.Len()))
	_ = binary.Write(&ico, binary.LittleEndian, uint32(22)) // the header's own length
	ico.Write(encoded.Bytes())
	return ico.Bytes(), nil
}

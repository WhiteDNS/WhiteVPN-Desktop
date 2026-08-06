"""Regenerate every icon in the app from one source image.

There are six of them in five places and they are easy to update partly, which
leaves an app whose taskbar icon disagrees with its sidebar. Run this instead:

    python scripts/make-icons.py path/to/logo.png

Sizes match what was there before, so nothing downstream has to change. The
source should be square and at least 1024x1024; anything smaller is upscaled and
will look it.
"""

import sys
from pathlib import Path

from PIL import Image

# Where each icon lives and how big it has to be. The .ico is a special case:
# Windows picks a size out of it per context, so it carries all of them.
TARGETS = [
    ("build/appicon.png", 1024),
    ("frontend/public/icon-512.png", 512),
    ("frontend/public/icon-192.png", 192),
    ("frontend/public/apple-touch-icon.png", 180),
    ("frontend/public/favicon.png", 64),
]
ICO_PATH = "build/windows/icon.ico"
ICO_SIZES = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
ICNS_PATH = "build/appicon.icns"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    source_path = Path(sys.argv[1])
    if not source_path.is_file():
        print(f"no such file: {source_path}")
        return 1

    root = Path(__file__).resolve().parent.parent
    source = Image.open(source_path).convert("RGBA")
    if source.width != source.height:
        # Squared by padding rather than cropping: a logo that loses its edges
        # to a crop is worse than one with a little space around it.
        side = max(source.size)
        square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        square.paste(source, ((side - source.width) // 2, (side - source.height) // 2))
        source = square
        print(f"source was {source_path.name} at a non-square size; padded to {side}x{side}")

    for relative, size in TARGETS:
        out = root / relative
        source.resize((size, size), Image.LANCZOS).save(out, "PNG")
        print(f"wrote {relative:42} {size}x{size}")

    out = root / ICO_PATH
    source.resize((256, 256), Image.LANCZOS).save(out, "ICO", sizes=ICO_SIZES)
    print(f"wrote {ICO_PATH:42} {', '.join(f'{w}x{h}' for w, h in ICO_SIZES)}")

    out = root / ICNS_PATH
    source.save(out, "ICNS")
    print(f"wrote {ICNS_PATH:42} macOS multi-resolution icon")

    print("\nRebuild for these to reach the app: the .ico is embedded in tray.go")
    print("and the taskbar icon is baked into the binary by wails build.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

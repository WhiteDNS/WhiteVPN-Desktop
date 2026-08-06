# Third-party notices and binary provenance

WhiteVPN Desktop includes or builds the following third-party components. Each
component remains under its upstream license; the repository's MIT license
does not replace those terms.

## Runtime components

### Mihomo / FlClash core

Release packages build the engine from source rather than committing a core
executable. The exact inputs are pinned in
[`desktop/scripts/setup-mihomo-core.sh`](desktop/scripts/setup-mihomo-core.sh):

- FlClash: `https://github.com/chen08209/FlClash.git`, commit
  `7c831855efedceb1a72bd0b4c18da026593d0853`.
- Mihomo: `https://github.com/MetaCubeX/mihomo.git`, tag `v1.19.29`.
- FlClash Mihomo patch: `https://github.com/chen08209/Clash.Meta.git`, commit
  `80362fc1895dcf60b79b562896653046e0687413`.

These sources are licensed under GPL-3.0. Their complete license text and
copyright notices are present in the pinned source checkouts produced by the
setup script. The build script records the version in the executable and uses
only those verified refs.

### Wintun

Windows packages include the official Wintun 0.14.1 amd64 DLL:

- Archive: `https://www.wintun.net/builds/wintun-0.14.1.zip`
- Archive member: `wintun/bin/amd64/wintun.dll`
- SHA-256: `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`
- License: [licenses/WINTUN-0.14.1.txt](licenses/WINTUN-0.14.1.txt)

The committed DLL was compared byte-for-byte with that archive member.

### shadcn Tailwind utilities

`desktop/frontend/src/shadcn.css` is the stylesheet from shadcn 4.7.0. The
small required CSS asset is vendored without the unused shadcn CLI dependency
tree. It is covered by [licenses/SHADCN-MIT.txt](licenses/SHADCN-MIT.txt).

## Build-only components

Linux AppImage packaging downloads linuxdeploy release
`1-alpha-20251107-1` from its official GitHub release and verifies SHA-256
`c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d`
before execution. linuxdeploy is a build tool and is not shipped inside the
application.

Go and npm dependency versions are locked in `go.sum` and
`desktop/frontend/package-lock.json`; their upstream license terms continue to
apply.

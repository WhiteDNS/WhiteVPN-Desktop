# WhiteVPN Desktop — developer notes

The project README is [one level up](../README.md): what the app is, how to
install it, and how to build it. This file is the detail that only matters once
you are working on the code.

Before changing anything, read [ANDROID-PARITY.md](./ANDROID-PARITY.md). It is
the specification — WhiteVPN for Android, setting by setting — and it records
every deliberate divergence from it, along with a section of failures that cost
real time to find.

The MasterDNS/StormDNS side of the original combined app lives on in
[WhiteDNS-Desktop](https://github.com/WhiteDNS/WhiteDNS-Desktop).

## Persian user-facing documents

- [Quick download guide](./DOWNLOAD_GUIDE_FA.md)
- [Release note for users](./RELEASE_NOTES_FA.md)
- [Telegram announcement draft](./TELEGRAM_ANNOUNCEMENT_FA.md)

## The engine

mihomo is the only engine. The Xray path this app started with was removed on
2026-08-04, and features written against it — IP fronting was one — turned out
to have been invisible in the shipping app the whole time. Anything that still
reads a field from that era is a bug; several were found by users noticing a
number that could not be true.

The engine is not vendored. `make mihomo-core` fetches FlClash and mihomo at
their pinned refs, applies the FlClash commit, and builds a plain executable
with `CGO_ENABLED=0` and `-tags=with_gvisor`. The result lands in
`cores/mihomo-<goos>-<goarch>` and is embedded into the app binary, so a
release is one file rather than a file and a folder that has to stay beside it.

Override the binary during development with `WHITEVPN_MIHOMO_BIN`.

## Verifying a change

From the repository root:

```bash
make test
```

Tests that need a real engine are gated behind environment variables and skip
otherwise:

```bash
WHITEVPN_MEASURE_LIVE=1 \
WHITEVPN_MIHOMO_BIN=/path/to/mihomo \
WHITEVPN_PROBE_SUB=/path/to/subscription.txt \
  go test ./internal/session -run Live -v
```

## Two traps worth knowing before they cost you an afternoon

**`wails build -s` skips the frontend.** The Go side rebuilds, the binary looks
new, and the interface inside it is whatever was last built properly. Two
rounds of "I fixed that, why is it still broken" came from this. Check the
timestamp on `frontend/dist/assets/*.js`, or look for `Compiling frontend: Done`.

**`exec.CommandContext` kills what it starts.** The context that lets a user
cancel a connect must never own the engine's lifetime. It did once, and every
proxy-mode connection died about a second after reporting success — while TUN
was untouched, because that path spawns through `ShellExecuteExW` where no
context can reach. `TestLiveConnectionOutlivesItsConnectContext` fails within
three seconds if it comes back.

The rest of that list lives in ANDROID-PARITY.md under *Things that will bite*.

## Make targets

```bash
make deps                        npm install and go mod tidy
make dev                         wails dev
make build                       frontend + Go binary
make test                        Go tests and the frontend build

make package-windows             per-platform release packages
make package-mac                 (must run on a Mac)
make package-linux               (must run on Linux)
make package-linux-distros       .deb and .rpm from a Linux build
make package-linux-all-docker    Linux packages from a non-Linux host

make mihomo-core                 build the engine for this host
make mihomo-core-setup           fetch the pinned engine source only
make clean                       remove build output and cached cores
```

Pass a version with `VERSION=1.0.0`, or the make-safe form
`make all -- --version 1.0.0`.

Linux packaging needs `dpkg-deb` and `rpmbuild`. For an AppImage, include
`appimage` in `LINUX_PACKAGE_FORMATS`; the script downloads linuxdeploy unless
`LINUXDEPLOY_BIN` points at a local copy. On Ubuntu 24.04+ pass
`LINUX_GO_TAGS=webkit2_41` and install `libwebkit2gtk-4.1-dev`.

## Where state lives

`<user config dir>/WhiteVPN Desktop/`:

- `state.json` — settings, subscriptions, and the selected node
- `mihomo/` — the live engine's home; `config.yaml` is written here
- `mihomo-measure/` — the second engine the Servers page tests with
- `system-proxy.json` — what the machine's proxy settings were before the app
  changed them. Present only while connected; if it survives a crash, startup
  restores from it before anything else can connect.

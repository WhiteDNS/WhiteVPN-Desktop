# WhiteVPN Desktop

A desktop VPN client for Windows, macOS and Linux, built to behave like
[WhiteVPN for Android](https://github.com/WhiteDNS/WhiteVPN) and to run the same
engine underneath it: [mihomo](https://github.com/MetaCubeX/mihomo), through
[FlClash](https://github.com/chen08209/FlClash)'s protocol glue.

Someone who has used the phone app should find the same options here, under
recognisable names, producing the same behaviour. Where the desktop needs
something the phone has no equivalent for — a tray icon, a system proxy, a
server workbench — it is added deliberately and recorded as a divergence in
[`desktop/ANDROID-PARITY.md`](desktop/ANDROID-PARITY.md).

[![Release](https://img.shields.io/github/v/release/WhiteDNS/WhiteVPN-Desktop?sort=semver)](https://github.com/WhiteDNS/WhiteVPN-Desktop/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

---

## What it does

- **Connects through a subscription** — the built-in catalogue, or any
  `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://` or
  `wireguard://` list you add.
- **Chooses for you, or lets you choose** — filter by country, by protocol, or
  pin one node by hand. A choice nothing matches is refused rather than
  silently ignored.
- **Reports what is true** — the status card shows the node's claimed country
  *and* the country of the address the internet actually sees, measured through
  the tunnel. When they disagree, the measurement wins and the tooltip says so.
- **Recovers on its own** — a connection is re-checked every 20 seconds and
  moves to another node if it stops carrying traffic. A node you pinned by hand
  is left alone and reported instead.
- **A server workbench** — test any subscription's nodes for reachability,
  delay and throughput; sort by any column; share a node's link.
- **Runs in the background** — closing the window hides it to the tray; the
  tunnel keeps running.
- **Speaks English and Persian**, laying the interface out right-to-left in
  Persian.

## Install

Grab the asset for your machine from the
[latest release](https://github.com/WhiteDNS/WhiteVPN-Desktop/releases/latest).

| Platform | Asset |
|---|---|
| Windows 10/11, Intel or AMD | `*-windows-x64.zip` |
| Windows on ARM (Snapdragon, Surface Pro X) | `*-windows-arm64-windows-on-arm.zip` |
| macOS, Apple Silicon | `*-macos-arm64.zip` |
| macOS, Intel | `*-macos-amd64.zip` |
| Debian, Ubuntu | `*-linux-amd64.deb` or `*-linux-arm64.deb` |
| Fedora, RHEL, openSUSE | `*-linux-amd64.rpm` or `*-linux-arm64.rpm` |
| Ubuntu 24.04+, Fedora 40+ (WebKitGTK 4.1) | the `*-linux-amd64-webkit41.*` assets |
| Any x86-64 Linux, no package manager | `*-linux-amd64-webkit41.AppImage` |
| Portable fallback | `.tar.gz` — needs GTK 3 and a matching WebKitGTK |

Download the ZIP from the release assets rather than a raw `.app` from a CI
artifact: artifact downloads strip the executable bit and macOS then refuses to
open the app.

## Known limitations

Stated plainly, because finding these out by surprise is worse than reading
them here.

| | Windows | macOS | Linux |
|---|:---:|:---:|:---:|
| Proxy mode | ✅ | ✅ | ✅ |
| System proxy set automatically | ✅ | ✅ | ⚠️ |
| TUN mode (whole-machine tunnel) | ✅ | 🚧 | 🚧 experimental |
| Signed / notarised binaries | ❌ | ❌ | n/a (root-owned packages) |

- **TUN ships on Windows; Linux and macOS are built but gated.** The
  privileged plumbing now exists on all three — a root-owned `whitevpn-helper`
  with polkit action for packaged Linux installs, an `SMAppService` launch
  daemon for macOS 13+ — and every tunnel start is verified against the kernel's
  own routing tables before it reports connected. Linux requires installing
  from `.deb`/`.rpm`/AUR plus starting the app once with
  `WHITEVPN_EXPERIMENTAL_TUN=1`; portable artifacts stay proxy-only by design.
  macOS needs a signed bundle (`MACOS_TEAM_ID` + `MACOS_SIGN_IDENTITY`) before
  its daemon will run anything. Both remain behind the experimental flag until
  the live matrices in [`docs/PLATFORM_SUPPORT_PLAN.md`](docs/PLATFORM_SUPPORT_PLAN.md)
  have been run. Proxy mode works everywhere.
- **Linux system-proxy support is desktop-specific.** The app probes, writes
  and restores GNOME-compatible `gsettings` and KDE's `kioslaverc`
  independently — each backend is captured and put back separately, so one
  refusing desktop never blocks another. A bare window manager has no shared
  setting to write; the interface says so plainly and applications are pointed
  at the local port manually.
- **Nothing is code-signed** on Windows; macOS bundles are ad-hoc signed until
  release credentials exist. macOS will refuse to open the app until you allow
  it in System Settings → Privacy & Security; Windows SmartScreen will warn.
- **The kill switch is not implemented** on any platform.

The implementation and rollout work needed to remove the first two limitations
is tracked in [`docs/PLATFORM_SUPPORT_PLAN.md`](docs/PLATFORM_SUPPORT_PLAN.md).

## Building

Requires Go 1.26.5+, Node 24+, and the [Wails v2](https://wails.io) CLI. The
mihomo engine is **not** in this repository — the build fetches its pinned
source and compiles it for the target, so a first build needs network access.

```bash
make deps
make test
make build
```

Platform packages:

```bash
make package-windows
make package-mac
make package-linux
make package-linux-distros
```

`make package-mac` must run on a Mac — the tray needs Cocoa, so the build needs
CGO and the macOS SDK. Windows and Linux cross-compile from anywhere; Wails
packaging for Linux still wants a Linux host or Docker
(`make package-linux-all-docker`).

The engine alone:

```bash
make mihomo-core TARGET_GOOS=darwin TARGET_GOARCH=arm64
```

Runtime state lives in the platform config directory, under
`WhiteVPN Desktop/state.json`.

## Releasing

Every platform is built by GitHub Actions. Tag and push:

```bash
git tag vpn-v1.0.0 && git push origin vpn-v1.0.0
```

The workflow builds seven targets and attaches the assets to a GitHub Release.
To check a build without publishing anything, run the workflow by hand from the
Actions tab — the publish step only runs for a `vpn-v*` tag.

## Repository layout

```
desktop/
  app.go, mihomo_connect.go     the app and its connect path
  internal/session/             one connected engine: config, health, recovery
  internal/engine/              the core process and its action protocol
  internal/mihomoconf/          share links and YAML → mihomo configuration
  internal/sysproxy/            pointing the machine at the local proxy
  frontend/                     React + TypeScript, Tailwind, shadcn/ui
  ANDROID-PARITY.md             the specification, and every divergence from it
```

`ANDROID-PARITY.md` is worth reading before changing anything. It records what
was measured rather than assumed, and a section — *Things that will bite* — of
failures that cost real time.

## Security

Please report vulnerabilities using the private process in
[SECURITY.md](SECURITY.md).

## License

WhiteVPN Desktop is licensed under the
[GNU General Public License, version 3](LICENSE). Bundled components retain
their upstream licences; their exact sources, versions, hashes, and licence
references are recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

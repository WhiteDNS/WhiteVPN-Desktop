# WhiteVPN Desktop

Wails v2 desktop client for the WhiteDNS VPN tunnel and V2Ray profiles, both served by a managed Xray core.

The MasterDNS/StormDNS side of the original combined app lives on in
[WhiteDNS-Desktop](https://github.com/WhiteDNS/WhiteDNS-Desktop).

## Release notes

- [Persian quick download guide](./DOWNLOAD_GUIDE_FA.md)
- [Persian release note for users](./RELEASE_NOTES_FA.md)
- [Persian Telegram announcement draft](./TELEGRAM_ANNOUNCEMENT_FA.md)

## Windows downloads

For normal 64-bit Windows 10/11 PCs, download the `Windows x64` package. This is the correct build for Intel and AMD processors.

Do not download `Windows ARM64` unless the device is specifically a Windows-on-ARM PC, such as a Snapdragon device or Surface Pro X. The ARM64 executable will show "This app can't run on your PC" on ordinary Intel/AMD 64-bit Windows.

## macOS downloads

For Apple Silicon Macs, download the `macos-arm64.zip` release asset. For Intel Macs, download `macos-amd64.zip`.

Use the ZIP from the GitHub Release assets. Do not distribute a raw `.app` folder from GitHub Actions artifacts, because artifact downloads can strip executable permissions and macOS will show "The application can't be opened."

## Development

```bash
make deps
make test
make dev
```

The app extracts its embedded Xray core from `cores/xray-<goos>-<goarch>`. Package targets reset `cores/`, prepare only the core and Xray geodata for the target platform, and embed them into the app binary. Release packages do not need a separate `cores/` folder beside the app.

The public proxy is always served by Xray-core pinned to `v26.3.27`. During packaging, `make` reuses a matching core from `.cache/xray/` or `cores/`; if missing, it downloads the requested XTLS release asset. For development overrides, set `WHITEVPN_XRAY_BIN=/absolute/path/to/xray`.

Runtime profile data is stored under the platform user config directory in `WhiteVPN Desktop/state.json`.

`make build-mac` and `make build-windows` can run from macOS. `make all` builds Linux packages from non-Linux hosts through Docker. If Docker is not available, run `make build-linux` on a Linux host or use the `Desktop Release Builds` GitHub Actions workflow.

`make all` builds stripped/minified release packages for the desktop matrix. The default matrix stages macOS amd64/arm64 separately, Windows amd64/arm64, and Linux amd64/arm64. Override `ALL_MACOS_PLATFORMS`, `ALL_WINDOWS_PLATFORMS`, or `ALL_LINUX_PLATFORMS` to change the matrix.

Linux release jobs also publish native distro packages and an amd64 AppImage. Linux x64 users who want the least package-manager friction should try the `.AppImage` first. Debian and Ubuntu users can use the `.deb` package, RPM-based distributions can use the `.rpm` package, and the `.tar.gz` archive remains available as a portable fallback that still needs GTK 3 plus the matching WebKitGTK runtime from the distribution.

For newer RPM-based distributions that provide WebKitGTK 4.1 instead of 4.0, use the `linux-amd64-webkit41.rpm` asset. The older WebKitGTK 4.0 Linux assets remain for older distributions.

Pass the release version with `VERSION=1.0.0-beta6`, or use the GNU-make-safe flag form `make all -- --version 1.0.0-beta6`. Release staging writes platform folders under `build/releases/all/` and versioned compressed assets such as `WhiteVPN-Desktop-1.0.0-beta6-macos-arm64.zip`.

For Ubuntu 24.04+ Linux builds, pass `LINUX_GO_TAGS=webkit2_41` and install `libwebkit2gtk-4.1-dev`. Ubuntu 22.04 builds can use the default WebKitGTK 4.0 dependency. To build native Linux packages locally, install `dpkg-deb` and `rpmbuild`, then run `make package-linux-distros`. To include an amd64 AppImage, also include `appimage` in `LINUX_PACKAGE_FORMATS`; the packaging script downloads linuxdeploy unless `LINUXDEPLOY_BIN` points to an executable local copy.

Useful targets:

```bash
make xray-core
make build
make package
make build-mac
make build-windows
make build-linux
make package-linux-distros
make package-linux-all-docker
make build-all
make all
make clean
```

# WhiteVPN Desktop

WhiteVPN Desktop is a Wails v2 VPN client for macOS, Windows, and Linux. It
uses the same pinned Mihomo-based engine as the WhiteVPN Android client and
supports subscriptions plus manually imported proxy configurations.

## Development

Prerequisites are Go 1.25, Node.js 24, npm, the Wails v2 CLI, and the native
Wails dependencies for your operating system.

```sh
make deps
make test
make dev
```

Release packages can be built with:

```sh
make build-mac
make build-windows
make build-linux
```

See [desktop/README.md](desktop/README.md) for platform and packaging details.

## Security and licensing

Please report vulnerabilities using the process in [SECURITY.md](SECURITY.md).
The application source is available under the [MIT License](LICENSE). Bundled
components retain their own licenses; exact sources, versions, and hashes are
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

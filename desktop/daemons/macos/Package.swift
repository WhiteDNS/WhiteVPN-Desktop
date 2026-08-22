// swift-tools-version:5.9
// WhiteVPN's privileged macOS daemon.
//
// Built as its own executable so the app bundle can sign it separately —
// which it must: launchd will only run a daemon whose code signature matches
// what SMAppService registered, and the UI is checked against the daemon by
// designated requirement on every connection.
import PackageDescription

let package = Package(
    name: "WhiteVPNDaemon",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "WhiteVPNDaemon",
            path: "Sources/WhiteVPNDaemon"
        )
    ]
)

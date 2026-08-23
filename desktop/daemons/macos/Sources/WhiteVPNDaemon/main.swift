// WhiteVPN's privileged macOS daemon.
//
// What it is: the one process on this machine that runs anything as root. The
// app bundle registers it through SMAppService; launchd starts it when a UI
// connects to its mach service; it launches, supervises and stops exactly one
// program — the mihomo core that ships inside this same signed bundle.
//
// What it refuses, and why:
//
//   - Any executable path from a caller. The core is resolved from this
//     bundle's own resources and its signature is verified against the team
//     requirement before it is run. A daemon that took dictation about what
//     to execute would be an escalation with a password prompt in front.
//   - Any caller whose code signature does not carry this app's designated
//     requirement. The audit token of every connection is checked before a
//     single message is answered.
//   - Any request shape beyond start/stop/status. No subscription content, no
//     shell strings, no working directories. The socket path is validated
//     (absolute, our naming, owned by the asking user) because the core must
//     dial back to something — and that something belongs to whoever asked.
//
// Lifecycle guarantee: the daemon keeps one generation of tunnel at a time.
// When the controlling XPC connection dies — app crash, force quit, kill —
// invalidation fires and the core is stopped cleanly. If it will not stop,
// it is killed. No orphaned root process outlives its UI.

import Foundation

// protocolVersion must match macossvc.ProtocolVersion on the Go side. The UI
// asks for status first; a mismatched version reads as "helper needs
// upgrading" instead of mysterious failures later.
let protocolVersion = 1

// expectedTeamID is provided by TeamID.swift, generated at build time from
// MACOS_TEAM_ID. It is the certificate organiser unit (OU) this build trusts
// for both itself and the core: every peer connection and every engine launch
// is checked against it. A build made with the placeholder value refuses to
// run anything as root rather than trust an unknown team.
// See macos-daemon in desktop/Makefile.

struct TunnelState {
    var process: Process?
    var controller: xpc_connection_t?

    mutating func stop(reason: String) {
        if let running = process, running.isRunning {
            DaemonLog.log("stopping core: \(reason)")
            running.terminate()
            let deadline = Date().addingTimeInterval(8)
            while running.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.1)
            }
            if running.isRunning {
                DaemonLog.log("core ignored SIGTERM; killing")
                kill(running.processIdentifier, SIGKILL)
            }
        }
        process = nil
    }
}

var state = TunnelState()
let stateQueue = DispatchQueue(label: "com.whitevpn.vpn.daemon.state")

// --- entry ------------------------------------------------------------------

if CommandLine.arguments.contains("--version") {
    print("whitevpn-daemon protocol \(protocolVersion)")
    exit(0)
}

DaemonLog.log("daemon starting (protocol \(protocolVersion))")
startListener()
dispatchMain()

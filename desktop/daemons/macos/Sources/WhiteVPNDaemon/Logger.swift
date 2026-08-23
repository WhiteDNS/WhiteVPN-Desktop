import Foundation
import os

// One log, prefixed on every line: whatever goes wrong in a root daemon had
// better be findable in Console without guessing whose message it was.
enum DaemonLog {
    private static let log = Logger(subsystem: "com.whitevpn.vpn.daemon", category: "daemon")

    static func log(_ message: String) {
        self.log.info("whitevpn-daemon: \(message, privacy: .public)")
    }

    static func error(_ message: String) {
        self.log.error("whitevpn-daemon: \(message, privacy: .public)")
    }
}

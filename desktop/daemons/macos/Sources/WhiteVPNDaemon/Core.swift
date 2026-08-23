import Foundation
import Security

// Starting the tunnel: resolve the core from this bundle, prove it is the one
// that was signed with this app, point it at a socket owned by the asking
// user, and own it from then on.

func startTunnel(socketPath: String, controller: xpc_connection_t, replyTo peer: xpc_connection_t) {
    stateQueue.async {
        // One tunnel at a time. A second start replaces the first — after the
        // first has been given the chance to leave properly.
        if let existing = state.process, existing.isRunning {
            state.stop(reason: "a new session is starting")
        }

        if let problem = SocketCheck.problem(with: socketPath, askingUID: PeerCheck.uid(of: controller)) {
            send("{\"ok\":false,\"error\":\"\(problem)\"}", to: peer)
            return
        }

        guard let core = CoreLocator.locate() else {
            send("{\"ok\":false,\"error\":\"the bundled engine is missing from this install\"}", to: peer)
            return
        }
        switch CoreLocator.verifySignature(of: core) {
        case .valid:
            break
        case .invalid(let why):
            DaemonLog.error("refusing the bundled engine: \(why)")
            send("{\"ok\":false,\"error\":\"the bundled engine failed its signature check\"}", to: peer)
            return
        }

        let process = Process()
        process.executableURL = core
        process.arguments = [socketPath]
        process.currentDirectoryURL = core.deletingLastPathComponent()
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/var/root",
        ]
        process.standardOutput = Pipe()
        process.standardError = Pipe()

        do {
            try process.run()
        } catch {
            send("{\"ok\":false,\"error\":\"the engine could not be started\"}", to: peer)
            return
        }

        state.process = process
        state.controller = controller

        watchExit(of: process)
        DaemonLog.log("core started as pid \(process.processIdentifier)")
        send("{\"ok\":true,\"version\":\(protocolVersion),\"running\":true,\"pid\":\(process.processIdentifier)}", to: peer)
    }
}

private func watchExit(of process: Process) {
    process.terminationHandler = { terminated in
        stateQueue.sync {
            if state.process === terminated {
                state.process = nil
                DaemonLog.log("core exited with status \(terminated.terminationStatus)")
            }
        }
    }
}

private func send(_ json: String, to peer: xpc_connection_t) {
    let response = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(response, "reply", json)
    xpc_connection_send_message(peer, response)
}

// --- socket validation ------------------------------------------------------

enum SocketCheck {
    /// Returns nil when the path is acceptable, otherwise the reason it is not.
    ///
    /// The socket belongs to the UI's process; these checks prove the thing we
    /// are pointing root code at really is that user's and not a swapped-in
    /// stranger's: our name shape, a real socket, owned by whoever asked, and
    /// closed to every other account.
    static func problem(with path: String, askingUID: uid_t) -> String? {
        if askingUID == 0 {
            return "the interface must never run as root"
        }
        guard path.hasPrefix("/"), path.contains("/") else {
            return "the control socket path must be absolute"
        }
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
        if !exists || isDirectory.boolValue && !exists {
            // Not there yet is fine: the UI creates the listener moments later.
            if !exists {
                return nil
            }
        }
        if isDirectory.boolValue {
            return "the control path is a directory"
        }
        let name = URL(fileURLWithPath: path).lastPathComponent
        guard name.hasPrefix("whitevpn-engine-"), name.hasSuffix(".sock") else {
            return "the control socket does not have this app's name"
        }
        return ownershipProblem(path: path, askingUID: askingUID)
    }

    private static func ownershipProblem(path: String, askingUID: uid_t) -> String? {
        var status = stat()
        guard lstat(path, &status) == 0 else {
            return "the control socket vanished mid-check"
        }
        guard (status.st_mode & S_IFMT) == S_IFSOCK else {
            return "the control path is not a socket"
        }
        if status.st_uid != askingUID {
            return "the control socket does not belong to the asking user"
        }
        if status.st_mode & (S_IRWXG | S_IRWXO) != 0 {
            return "the control socket is open to other accounts"
        }
        return nil
    }
}

// --- core location and verification -----------------------------------------

enum CoreLocator {
    enum SignatureVerdict {
        case valid
        case invalid(String)
    }

    /// The core ships inside this bundle's resources, built for whichever
    /// machine this daemon runs on. There is no other place it will ever look,
    /// and no argument can change its mind.
    static func locate() -> URL? {
        guard let resources = Bundle.main.resourceURL else { return nil }
        return URL(fileURLWithPath: resources.path)
            .appendingPathComponent("cores/mihomo-darwin-\(currentArchitectureSuffix())")
    }

    private static func currentArchitectureSuffix() -> String {
        #if arch(arm64)
        return "arm64"
        #else
        return "amd64"
        #endif
    }

    /// The signature must chain to this app's team — the same check applied to
    /// every caller, now applied to the program about to run as root. A
    /// replaced or re-signed core fails here instead of starting.
    static func verifySignature(of url: URL) -> SignatureVerdict {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return .invalid("could not open the engine for checking")
        }
        guard expectedTeamID != "REPLACE_WITH_SIGNING_TEAM_ID", !expectedTeamID.isEmpty else {
            // An unsigned development build cannot prove anything; running an
            // unchecked binary as root is exactly what this check exists to
            // prevent.
            return .invalid("no signing team configured for this build")
        }
        let requirement = "anchor apple generic and certificate leaf[subject.OU] = \"\(expectedTeamID)\""
        var secRequirement: SecRequirement?
        guard let data = requirement.data(using: .utf8),
              SecRequirementCreateWithData(data as CFData, [], &secRequirement) == errSecSuccess,
              let secRequirement else {
            return .invalid("could not compile the engine requirement")
        }
        let status = SecStaticCodeCheckValidity(staticCode, [], secRequirement)
        return status == errSecSuccess ? .valid : .invalid("signature check failed (\(status))")
    }
}

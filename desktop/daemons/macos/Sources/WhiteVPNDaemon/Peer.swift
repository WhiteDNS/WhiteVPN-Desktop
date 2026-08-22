import Foundation
import Security

// Not every XPC/Security entry point is surfaced to Swift; this one has no
// replacement at all — it is how a server learns which exact code instance is
// on the other end of a connection.
@_silgen_name("xpc_connection_get_audit_token")
private func xpc_connection_get_audit_token(
    _ connection: xpc_connection_t,
    _ token: UnsafeMutablePointer<audit_token_t>
)

// Who is allowed to talk to this daemon, decided once per connection and
// never per message: the audit token names the exact code instance at the
// other end, and its designated requirement must carry our team identity.
// Anything else — another user's copy of the app, a re-signed binary, a
// script speaking XPC by hand — is refused before it can ask for anything.

enum PeerCheck {
    static func isTrusted(_ connection: xpc_connection_t) -> Bool {
        guard !expectedTeamID.isEmpty,
              expectedTeamID != "REPLACE_WITH_SIGNING_TEAM_ID" else {
            DaemonLog.error("no signing team configured; refusing every connection")
            return false
        }

        var token = audit_token_t()
        xpc_connection_get_audit_token(connection, &token)
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }

        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else {
            DaemonLog.error("could not identify the connecting process")
            return false
        }

        let requirementText =
            "anchor apple generic and certificate leaf[subject.OU] = \"\(expectedTeamID)\""
        var requirement: SecRequirement?
        guard let data = requirementText.data(using: .utf8),
              SecRequirementCreateWithData(data as CFData, [], &requirement) == errSecSuccess,
              let requirement else {
            DaemonLog.error("could not compile the peer requirement")
            return false
        }

        let status = SecCodeCheckValidityWithErrors(code, [], requirement, nil)
        if status != errSecSuccess {
            DaemonLog.error("peer failed the team check (\(status))")
            return false
        }
        return true
    }

    /// The user behind the connection. The daemon runs as root; the socket it
    /// is pointed at must belong to whoever is actually asking.
    static func uid(of connection: xpc_connection_t) -> uid_t {
        xpc_connection_get_euid(connection)
    }
}

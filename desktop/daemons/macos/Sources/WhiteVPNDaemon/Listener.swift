import Foundation

// The mach service listener. launchd owns the name (com.whitevpn.vpn.daemon,
// declared in the bundle's LaunchDaemons plist) and hands us each inbound
// connection; nothing here creates or claims the service itself, because that
// is what makes on-demand start and restart the kernel's job instead of ours.

func startListener() {
    let listener = xpc_connection_create_mach_service(
        "com.whitevpn.vpn.daemon",
        DispatchQueue(label: "com.whitevpn.vpn.daemon.listener"),
        UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
    )

    xpc_connection_set_event_handler(listener) { event in
        switch xpc_get_type(event) {
        case XPC_TYPE_CONNECTION:
            accept(peer: event)

        case XPC_TYPE_ERROR:
            DaemonLog.log("listener error: \(String(describing: event))")

        default:
            break
        }
    }
    xpc_connection_resume(listener)
}

private func accept(peer: xpc_connection_t) {
    guard PeerCheck.isTrusted(peer) else {
        // Cancelled without ever being resumed: the connection simply never
        // existed from the peer's point of view.
        xpc_connection_cancel(peer)
        return
    }

    xpc_connection_set_event_handler(peer) { event in
        switch xpc_get_type(event) {
        case XPC_TYPE_DICTIONARY:
            handle(message: event, from: peer)

        case XPC_TYPE_ERROR:
            // The controlling UI went away — crash, quit, kill. Whatever the
            // cause, its tunnel must not outlive it. Identity matters: a
            // replacement session may already own a newer tunnel, and this
            // stale connection's death must not reach into it.
            if event === XPC_ERROR_CONNECTION_INVALID || event === XPC_ERROR_CONNECTION_INTERRUPTED {
                stateQueue.sync {
                    let wasCurrent = state.controller === peer
                    state.controller = nil
                    if wasCurrent {
                        state.stop(reason: "the controlling app disconnected")
                    }
                }
            }
        default:
            break
        }
    }
    xpc_connection_resume(peer)
}

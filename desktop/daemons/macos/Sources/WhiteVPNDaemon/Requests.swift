import Foundation

// The whole request schema: status, start, stop. Anything else in a message is
// refused rather than interpreted — a daemon that grows an argument for every
// feature eventually grows one that runs something.

private func send(_ replyJSON: String, to peer: xpc_connection_t) {
    let response = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(response, "reply", replyJSON)
    xpc_connection_send_message(peer, response)
}

func handle(message: xpc_object_t, from peer: xpc_connection_t) {
    guard let method = xpc_dictionary_get_string(message, "method") else {
        send("{\"ok\":false,\"error\":\"no method in request\"}", to: peer)
        return
    }

    switch String(cString: method) {
    case "status":
        let snapshot = stateQueue.sync { runningJSON() }
        send(snapshot, to: peer)

    case "start":
        let argument = xpc_dictionary_get_string(message, "argument").map { String(cString: $0) } ?? ""
        startTunnel(socketPath: argument, controller: peer, replyTo: peer)

    case "stop":
        stateQueue.sync { state.stop(reason: "the app asked") }
        send("{\"ok\":true,\"version\":\(protocolVersion)}", to: peer)

    default:
        send("{\"ok\":false,\"error\":\"unknown method\"}", to: peer)
    }
}

private func runningJSON() -> String {
    if let core = state.process, core.isRunning {
        return "{\"ok\":true,\"version\":\(protocolVersion),\"running\":true,\"pid\":\(core.processIdentifier)}"
    }
    return "{\"ok\":true,\"version\":\(protocolVersion),\"running\":false}"
}

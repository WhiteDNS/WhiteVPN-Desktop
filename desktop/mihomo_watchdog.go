package main

import (
	"context"
	"fmt"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
)

// How often a live connection is asked to prove itself, and how many times in a
// row it has to fail before the node is given up on.
//
// Twenty seconds is short enough that a user notices the recovery rather than
// the outage, and two failures rather than one because a single probe can lose
// to a moment of nothing — a laptop waking, a wifi handover — and moving node
// for that would be worse than waiting for the next check.
const (
	healthWatchInterval = 20 * time.Second
	healthWatchFailures = 2
	// How many alternatives one recovery tries before giving the old node back.
	healthWatchAttempts = 5
)

// watchHealth keeps a connection working after it has been made.
//
// Connecting proves a node carries traffic and then pins the group to it. That
// proof has a shelf life: a user's log showed the node behind a CDN answering
// 502 to every request while the app sat there reporting Connected, green
// badge, zero bytes. Nothing was ever going to notice, because nothing was
// looking after the first successful request.
func (a *App) watchHealth(current *session.Session) {
	go func() {
		ticker := time.NewTicker(healthWatchInterval)
		defer ticker.Stop()

		failures := 0
		for range ticker.C {
			// This watcher belongs to one session; a replaced or stopped one
			// gets its own.
			if a.mihomo.current() != current {
				return
			}
			a.mu.Lock()
			status := a.state.Runtime.Status
			pinned := a.state.WhiteVPN.Connection.Node != ""
			a.mu.Unlock()
			if status != model.RuntimeConnected {
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			ok := current.Healthy(ctx)
			cancel()
			if ok {
				if failures > 0 {
					a.appendRuntimeLog("the connection answered again")
				}
				failures = 0
				continue
			}

			failures++
			a.appendRuntimeLog(fmt.Sprintf(
				"the connection carried nothing (%d of %d checks)", failures, healthWatchFailures))
			if failures < healthWatchFailures {
				continue
			}
			failures = 0

			if pinned {
				// The node was chosen by hand. Moving off it would be answering
				// a question the user already answered, so this only says so.
				a.appendRuntimeLog("the chosen node is not carrying traffic; pick another on the VPN page")
				a.emit("runtime:error", "The node you chose has stopped carrying traffic. Pick another, or set the connection back to Automatic.")
				continue
			}
			a.recoverConnection(current)
		}
	}()
}

// recoverConnection moves a stranded connection onto a node that works.
func (a *App) recoverConnection(current *session.Session) {
	a.appendRuntimeLog("looking for a node that works")
	a.handleRuntimeState(model.RuntimeConnecting, "The node stopped answering — finding another")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	node, err := current.Recover(ctx, healthWatchAttempts)
	if a.mihomo.current() != current {
		// Stopped or replaced while this was running; its outcome is about a
		// connection that no longer exists.
		return
	}
	if err != nil {
		a.appendRuntimeLog(err.Error())
		// Still connected, on the node it had: the status goes back to what it
		// was rather than to failed, because the proxy is up and the old node
		// may recover.
		a.handleRuntimeState(model.RuntimeConnected, fmt.Sprintf("Proxy listening on 127.0.0.1:%d", current.MixedPort()))
		a.emit("runtime:error", "The connection stopped working and no other node answered either.")
		return
	}

	a.appendRuntimeLog(fmt.Sprintf("moved to %q", node))
	a.recordConnectedNode(node)
	a.handleRuntimeState(model.RuntimeConnected, fmt.Sprintf("Proxy listening on 127.0.0.1:%d", current.MixedPort()))
	a.resolveExitCountry()
}

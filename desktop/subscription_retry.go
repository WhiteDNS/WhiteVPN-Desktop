package main

// Refreshing what the network was blocking, once there is a way past it.
//
// A subscription whose address is blocked locally can only be fetched through
// the tunnel, which means connecting first and refreshing second. That order is
// not discoverable: the only place it is written down is the error you get for
// doing it the other way round, and the same user hit it twice — once before the
// message said so and once after. An instruction people have to read and then
// remember to act on is a step the app can take itself.
//
// So a successful connection retries the subscriptions that have nothing in
// them. Only those: a subscription that already imported nodes is not waiting on
// anything, and refreshing every one on every connect would put a burst of
// requests on the provider each time somebody reconnects.

import (
	"fmt"
	"sync/atomic"
)

// retryingBlockedSubscriptions keeps two connects in quick succession — a
// reconnect, a network change — from running this twice at once.
var retryingBlockedSubscriptions atomic.Bool

// retryBlockedSubscriptions refreshes empty subscriptions now that the tunnel is
// up, in the background.
//
// In the background because it is a courtesy, not part of connecting: the
// connection is already usable and must not wait on someone else's server.
func (a *App) retryBlockedSubscriptions() {
	if !retryingBlockedSubscriptions.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer retryingBlockedSubscriptions.Store(false)
		a.refreshEmptySubscriptions()
	}()
}

func (a *App) refreshEmptySubscriptions() {
	ids := a.emptySubscriptionIDs()
	if len(ids) == 0 {
		return
	}

	refreshed := false
	for _, id := range ids {
		result, err := a.RefreshV2RaySubscription(id)
		if err != nil {
			// Worth a line and nothing more. This ran because the connection
			// came up, not because anyone asked for it, so a failure here must
			// not surface as though an action of theirs had failed — the row in
			// the list carries the reason already.
			a.appendRuntimeLog(fmt.Sprintf("could not refresh %q now that the connection is up: %v", id, err))
			continue
		}
		refreshed = true
		a.appendRuntimeLog(fmt.Sprintf(
			"refreshed %q through the connection: %d configs",
			result.Subscription.Name, result.Subscription.ImportedCount,
		))
	}
	if refreshed {
		// The list on screen still shows the failure that sent this here.
		a.emit("subscriptions:changed", nil)
	}
}

// emptySubscriptionIDs is the subscriptions a working connection might fill.
//
// The built-in catalogue is skipped: connecting is what fetches it, so by the
// time this runs it has either just succeeded or the connection would not be up.
func (a *App) emptySubscriptionIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	var ids []string
	for _, subscription := range a.state.V2RaySubscriptions {
		if subscription.ID == whiteDNSVPNSubscriptionID {
			continue
		}
		if subscription.ImportedCount > 0 && subscription.LastError == "" {
			continue
		}
		ids = append(ids, subscription.ID)
	}
	return ids
}

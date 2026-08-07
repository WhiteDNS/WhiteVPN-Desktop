package main

// The catalogue, as something a person can choose from.
//
// Everything the dashboard's two dialogs need is already in the names the
// catalogue ships. One looks like this:
//
//	🇩🇪 | @WhiteDNS | DE1|36.8MB/s|DNSOK|GPT⁺-DE|CL-DE|SP-DE
//
// The leading flag is a pair of regional indicator symbols, and those are
// letters: 🇩🇪 is D followed by E. That is where the location filter's country
// codes come from — no lookup, no network round trip, and no geoip database to
// disagree with the catalogue about where a node is. Nodes the catalogue marks
// ❓ get no country, and are reachable only with the filter off.

import (
	"context"
	"fmt"

	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/engine"
	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/profiles"
)

const (
	// regionalIndicatorA is 🇦. The 26 symbols from here map onto A–Z.
	regionalIndicatorA = '\U0001F1E6'
	regionalIndicatorZ = '\U0001F1FF'

	// whiteVPNDelayConcurrency bounds a measuring run. The catalogue holds
	// hundreds of nodes and each measurement is a request through the core;
	// asking for all of them at once measures the core's queue rather than the
	// nodes.
	whiteVPNDelayConcurrency = 16
	whiteVPNDelayTimeout     = 5 * time.Second
	// whiteVPNDelayLimit caps one run. Sorting a list by delay does not require
	// measuring a list nobody has scrolled to.
	whiteVPNDelayLimit = 120

	// whiteVPNLiveSwitchAttempts bounds how long changing a dashboard row can
	// take. Each attempt is a health check with its own budget, and a user who
	// picked a country is owed an answer, not a spinner working through it.
	whiteVPNLiveSwitchAttempts = 3
)

// ListWhiteVPNNodes returns the catalogue for the connection dialog.
//
// It is cached for as long as the subscription itself is, so opening the dialog
// costs nothing after the first time; refresh forces a fetch for the case where
// a user believes the catalogue has moved on.
func (a *App) ListWhiteVPNNodes(refresh bool) (model.WhiteVPNNodeList, error) {
	return a.ListSubscriptionNodes(a.selectedSubscriptionID(), refresh)
}

// ListSubscriptionNodes returns any subscription's nodes, which is what lets
// the Servers page look at one the VPN is not connecting through. Each keeps
// its own cache, so looking at one does not disturb the other.
func (a *App) ListSubscriptionNodes(subscriptionID string, refresh bool) (model.WhiteVPNNodeList, error) {
	subscriptionID = strings.TrimSpace(subscriptionID)
	if subscriptionID == "" {
		subscriptionID = a.selectedSubscriptionID()
	}
	if !refresh {
		if cached, ok := a.cachedWhiteVPNNodes(subscriptionID, time.Now().UTC()); ok {
			return cached, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	subscription, err := a.subscriptionBodyFor(ctx, subscriptionID)
	if err != nil {
		return a.staleWhiteVPNNodes(subscriptionID, err)
	}
	nodes, err := whiteVPNNodesFromSubscription(subscription)
	if err != nil {
		return a.staleWhiteVPNNodes(subscriptionID, err)
	}
	if subscriptionID == model.ManualServerSourceID {
		a.attachManualProfileIDs(nodes)
	}
	a.markHiddenNodes(subscriptionID, nodes)
	return a.storeWhiteVPNNodes(subscriptionID, nodes, time.Now().UTC()), nil
}

// markHiddenNodes flags the nodes the user has taken out of this subscription.
//
// Flagged rather than dropped: a node removed from the list could never be put
// back, so hiding would be a one-way door with no way out of it.
func (a *App) markHiddenNodes(subscriptionID string, nodes []model.WhiteVPNNode) {
	hidden := a.hiddenNodeNames(subscriptionID)
	if len(hidden) == 0 {
		return
	}
	lookup := make(map[string]struct{}, len(hidden))
	for _, name := range hidden {
		lookup[name] = struct{}{}
	}
	for i := range nodes {
		_, nodes[i].Hidden = lookup[nodes[i].Name]
	}
}

// attachManualProfileIDs points each manually added node back at the profile it
// was made from, which is what lets the Servers page edit and delete it.
//
// The match is on the share link rather than on position. Both sides come from
// the same exporter — `subscriptionBodyFor` builds the manual body by running
// every profile through `ExportV2RayProfile`, and the parser hands back the link
// each node arrived as — so the strings are identical where they correspond. On
// position they would not be: the exporter skips profiles it cannot express and
// the parser skips proxies it cannot use, so one incomplete profile would shift
// every row after it onto the wrong config. Deleting the wrong node because two
// lists drifted is not a mistake worth risking to save a map.
func (a *App) attachManualProfileIDs(nodes []model.WhiteVPNNode) {
	a.mu.Lock()
	stored := make([]model.V2RayProfile, 0, len(a.state.V2RayProfiles))
	for _, profile := range a.state.V2RayProfiles {
		if profile.SubscriptionID == "" {
			stored = append(stored, profile)
		}
	}
	a.mu.Unlock()

	byLink := make(map[string]string, len(stored))
	for _, profile := range stored {
		link, err := profiles.ExportV2RayProfile(profile)
		if err != nil {
			continue
		}
		// First writer wins: two identical configs saved twice are the same node
		// as far as the list is concerned, and the earlier profile is the one the
		// row has been showing.
		if _, taken := byLink[link]; !taken {
			byLink[link] = profile.ID
		}
	}

	for i := range nodes {
		nodes[i].ProfileID = byLink[nodes[i].Link]
	}
}

// SaveWhiteVPNSelection stores the dashboard's location and connection choices,
// and keeps a live connection honest about them.
//
// Three things have to hold together here. A choice nothing in the catalogue
// satisfies is refused rather than stored, because a stored one would fail at
// the next connect with no clue as to why. A choice that is stored while
// something is running is applied to it, because a row reading Germany above a
// connection leaving from Japan is a lie the interface would be telling. And a
// node that will not carry traffic leaves the previous one in place — see
// session.Select.
func (a *App) SaveWhiteVPNSelection(countryCode string, selection model.ConnectionSelection) (model.AppState, error) {
	a.mu.Lock()
	next := model.NormalizeWhiteVPNSettings(a.state.WhiteVPN)
	a.mu.Unlock()
	next.CountryCode = countryCode
	next.Connection = selection
	next = model.NormalizeWhiteVPNSettings(next)

	var allowed []string
	if selectionIsNarrowed(next) {
		nodes, err := a.nodesForSelection()
		if err != nil {
			return a.GetAppState(), err
		}
		allowed = preferredNodeNames(nodes, next)
		if len(allowed) == 0 {
			return a.GetAppState(), fmt.Errorf("no node in the catalogue matches that choice")
		}
	}

	state, err := a.SaveWhiteVPNSettings(next)
	if err != nil {
		return state, err
	}
	if err := a.applySelectionToLiveSession(allowed); err != nil {
		return a.GetAppState(), err
	}
	return a.GetAppState(), nil
}

// applySelectionToLiveSession moves a running connection onto a node the new
// choice allows, and leaves it alone when the node it is already using does.
func (a *App) applySelectionToLiveSession(allowed []string) error {
	current := a.mihomo.current()
	if current == nil || len(allowed) == 0 {
		return nil
	}
	for _, name := range allowed {
		if name == current.Selected() {
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var lastErr error
	for i, name := range allowed {
		if i >= whiteVPNLiveSwitchAttempts {
			break
		}
		if err := current.Select(ctx, name); err == nil {
			a.appendRuntimeLog(fmt.Sprintf("switched to %q", name))
			a.recordConnectedNode(name)
			a.resolveExitCountry()
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("the choice is saved, but no node matching it carried traffic: %w", lastErr)
}

// nodesForSelection is the catalogue a choice is checked against, fetched if it
// is not already known.
func (a *App) nodesForSelection() ([]model.WhiteVPNNode, error) {
	if nodes := a.whiteVPNNodesSnapshot(a.selectedSubscriptionID()); len(nodes) > 0 {
		return nodes, nil
	}
	list, err := a.ListWhiteVPNNodes(false)
	if err != nil {
		return nil, err
	}
	return list.Nodes, nil
}

// MeasureWhiteVPNNodeDelays measures the nodes named, through the running
// engine, and returns the catalogue with those measurements filled in.
//
// It needs a session, because a delay is measured through the core and there is
// no core when nothing is connected. That is worth saying plainly rather than
// returning a list of zeroes that looks like every node being instant.
func (a *App) MeasureWhiteVPNNodeDelays(names []string) (model.WhiteVPNNodeList, error) {
	// Through the live engine, so this is the connected subscription's nodes and
	// no other's.
	subscriptionID := a.selectedSubscriptionID()
	current := a.mihomo.current()
	if current == nil {
		return a.snapshotWhiteVPNNodes(subscriptionID), fmt.Errorf("delays are measured through the engine, so they need a connection")
	}
	if len(names) > whiteVPNDelayLimit {
		names = names[:whiteVPNDelayLimit]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	measured := measureNodeDelays(ctx, current.Engine(), names)
	return a.applyWhiteVPNNodeDelays(subscriptionID, measured), nil
}

type nodeDelay struct {
	delayMs int
	ok      bool
}

func measureNodeDelays(ctx context.Context, client *engine.Process, names []string) map[string]nodeDelay {
	results := make(map[string]nodeDelay, len(names))
	if client == nil {
		return results
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	gate := make(chan struct{}, whiteVPNDelayConcurrency)
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			select {
			case gate <- struct{}{}:
				defer func() { <-gate }()
			case <-ctx.Done():
				return
			}

			callCtx, cancel := context.WithTimeout(ctx, whiteVPNDelayTimeout+2*time.Second)
			defer cancel()
			delay, err := client.TestDelayMS(callCtx, node, mihomoconf.DelayTestURL, int(whiteVPNDelayTimeout/time.Millisecond))

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// A node that will not answer a probe can still carry traffic,
				// so this is recorded as "no measurement", never as a verdict.
				results[node] = nodeDelay{}
				return
			}
			results[node] = nodeDelay{delayMs: delay, ok: true}
		}(name)
	}
	wg.Wait()
	return results
}

// whiteVPNNodesFromSubscription turns a decrypted catalogue into nodes, in the
// order the catalogue gave them — which is the order the connect path tries.
func whiteVPNNodesFromSubscription(subscription string) ([]model.WhiteVPNNode, error) {
	// ParseSubscription rather than ConvertLinksWithSources: a subscription may
	// be share links or a whole mihomo configuration, and the Servers page, the
	// tests and the connection dialog have no business knowing which.
	proxies, sources, err := mihomoconf.ParseSubscription(subscription)
	if err != nil {
		return nil, fmt.Errorf("the catalogue held no usable nodes: %w", err)
	}
	nodes := make([]model.WhiteVPNNode, 0, len(proxies))
	for index, proxy := range proxies {
		name := proxy.Name()
		if strings.TrimSpace(name) == "" {
			continue
		}
		proxyType, _ := proxy["type"].(string)
		server, _ := proxy["server"].(string)
		transport, _ := proxy["network"].(string)
		tls, _ := proxy["tls"].(bool)
		nodes = append(nodes, model.WhiteVPNNode{
			Name:        name,
			Label:       nodeLabel(name),
			Type:        strings.ToLower(strings.TrimSpace(proxyType)),
			CountryCode: countryCodeFromNodeName(name),
			Server:      strings.TrimSpace(server),
			Port:        proxyPort(proxy),
			Transport:   strings.ToLower(strings.TrimSpace(transport)),
			TLS:         tls,
			Link:        sources[index],
		})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("the catalogue held no usable nodes")
	}
	return nodes, nil
}

// proxyPort reads the port whichever way the converter wrote it: YAML numbers
// arrive as int here and as float64 through JSON.
func proxyPort(proxy mihomoconf.Proxy) int {
	switch value := proxy["port"].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	}
	return 0
}

// countryCodeFromNodeName reads the flag the catalogue puts at the front of a
// name. An unknown flag, or none, means the node has no country: it is not
// guessed from the server address, because a guess that disagrees with the
// catalogue is worse than an honest blank.
func countryCodeFromNodeName(name string) string {
	letters := make([]rune, 0, 2)
	for _, r := range strings.TrimSpace(name) {
		if r < regionalIndicatorA || r > regionalIndicatorZ {
			break
		}
		letters = append(letters, 'A'+(r-regionalIndicatorA))
		if len(letters) == 2 {
			return string(letters)
		}
	}
	return ""
}

// nodeLabel drops what every row would repeat — the flag, which the row shows
// as its own column, and the channel marker, which is the same for all of them.
func nodeLabel(name string) string {
	kept := make([]string, 0, 8)
	for _, segment := range strings.Split(name, "|") {
		trimmed := strings.TrimSpace(segment)
		if trimmed == "" || strings.HasPrefix(trimmed, "@") || isFlagOnly(trimmed) {
			continue
		}
		kept = append(kept, trimmed)
	}
	if len(kept) == 0 {
		return strings.TrimSpace(name)
	}
	return strings.Join(kept, " · ")
}

func isFlagOnly(value string) bool {
	found := false
	for _, r := range value {
		if r >= regionalIndicatorA && r <= regionalIndicatorZ {
			found = true
			continue
		}
		// ❓ is the catalogue's own marker for a node it cannot place.
		if r == '❓' || r == ' ' {
			found = true
			continue
		}
		return false
	}
	return found
}

// preferredNodeNames is what the dashboard's choices mean on the connect path:
// which nodes may be tried, and in what order.
//
// An explicit pick yields exactly that node. A filter that matches nothing
// yields nothing, and the caller must refuse to connect rather than fall back to
// the whole catalogue — a user who asked for Germany and silently got Japan has
// been lied to about where their traffic goes.
func preferredNodeNames(nodes []model.WhiteVPNNode, settings model.WhiteVPNSettings) []string {
	// A hidden node is not in the configuration, so preferring one would name a
	// node the engine does not hold and fail the connect with a confusing error
	// about a choice matching nothing.
	if node := strings.TrimSpace(settings.Connection.Node); node != "" {
		for _, candidate := range nodes {
			if candidate.Name == node && !candidate.Hidden {
				return []string{candidate.Name}
			}
		}
		// The pick is no longer in the catalogue. Saying so beats connecting
		// somewhere else under the name of a choice the user made.
		return nil
	}

	country := model.NormalizeCountryCode(settings.CountryCode)
	types := map[string]bool{}
	for _, value := range settings.Connection.Types {
		types[strings.ToLower(strings.TrimSpace(value))] = true
	}
	if country == "" && len(types) == 0 {
		// Nothing narrowed: the catalogue's own order, which is what the phone
		// uses when the dashboard says Automatic.
		return nil
	}

	names := make([]string, 0, len(nodes))
	for _, candidate := range nodes {
		if candidate.Hidden {
			continue
		}
		if country != "" && candidate.CountryCode != country {
			continue
		}
		if len(types) > 0 && !types[candidate.Type] {
			continue
		}
		names = append(names, candidate.Name)
	}
	return names
}

// selectionIsNarrowed reports whether the settings ask for anything the whole
// catalogue would not satisfy, so an empty preference can be told apart from no
// preference at all.
func selectionIsNarrowed(settings model.WhiteVPNSettings) bool {
	return strings.TrimSpace(settings.Connection.Node) != "" ||
		model.NormalizeCountryCode(settings.CountryCode) != "" ||
		len(settings.Connection.Types) > 0
}

// forgetWhiteVPNNodes drops the cached catalogue, for when it belongs to a
// subscription that is no longer the selected one.
func (a *App) forgetWhiteVPNNodes(subscriptionID string) {
	a.nodesMu.Lock()
	delete(a.nodes, subscriptionID)
	delete(a.nodesAt, subscriptionID)
	a.nodesMu.Unlock()
}

// forgetAllCachedNodes drops every subscription's catalogue, for a reset: the
// measurements and node lists belong to state that no longer exists.
func (a *App) forgetAllCachedNodes() {
	a.nodesMu.Lock()
	a.nodes = map[string][]model.WhiteVPNNode{}
	a.nodesAt = map[string]time.Time{}
	a.nodesMu.Unlock()
}

func (a *App) cachedWhiteVPNNodes(subscriptionID string, now time.Time) (model.WhiteVPNNodeList, bool) {
	a.nodesMu.Lock()
	defer a.nodesMu.Unlock()
	fetchedAt, ok := a.nodesAt[subscriptionID]
	if !ok || len(a.nodes[subscriptionID]) == 0 {
		return model.WhiteVPNNodeList{}, false
	}
	if age := now.Sub(fetchedAt); age < 0 || age >= whiteDNSVPNSubscriptionRefreshInterval {
		return model.WhiteVPNNodeList{}, false
	}
	return a.nodeListLocked(subscriptionID), true
}

// staleWhiteVPNNodes answers a failed refresh with whatever is already known.
// A dialog that empties itself because the network blinked is worse than one
// showing a list from an hour ago alongside the error.
func (a *App) staleWhiteVPNNodes(subscriptionID string, err error) (model.WhiteVPNNodeList, error) {
	a.nodesMu.Lock()
	list := a.nodeListLocked(subscriptionID)
	a.nodesMu.Unlock()
	return list, err
}

func (a *App) snapshotWhiteVPNNodes(subscriptionID string) model.WhiteVPNNodeList {
	a.nodesMu.Lock()
	defer a.nodesMu.Unlock()
	return a.nodeListLocked(subscriptionID)
}

// storeWhiteVPNNodes keeps the catalogue, preserving delays already measured
// for nodes that are still in it.
func (a *App) storeWhiteVPNNodes(subscriptionID string, nodes []model.WhiteVPNNode, now time.Time) model.WhiteVPNNodeList {
	a.nodesMu.Lock()
	defer a.nodesMu.Unlock()
	if a.nodes == nil {
		a.nodes = map[string][]model.WhiteVPNNode{}
		a.nodesAt = map[string]time.Time{}
	}

	previous := make(map[string]model.WhiteVPNNode, len(a.nodes[subscriptionID]))
	for _, node := range a.nodes[subscriptionID] {
		previous[node.Name] = node
	}
	next := make([]model.WhiteVPNNode, 0, len(nodes))
	for _, node := range nodes {
		if earlier, ok := previous[node.Name]; ok {
			node.DelayMs, node.DelayOK, node.DelayTested, node.DelayError = earlier.DelayMs, earlier.DelayOK, earlier.DelayTested, earlier.DelayError
			node.ReachMs, node.ReachOK, node.ReachTested, node.ReachError = earlier.ReachMs, earlier.ReachOK, earlier.ReachTested, earlier.ReachError
			node.SpeedBytesPerSecond, node.SpeedOK, node.SpeedTested, node.SpeedError = earlier.SpeedBytesPerSecond, earlier.SpeedOK, earlier.SpeedTested, earlier.SpeedError
		}
		next = append(next, node)
	}

	a.nodes[subscriptionID] = next
	a.nodesAt[subscriptionID] = now
	return a.nodeListLocked(subscriptionID)
}

func (a *App) applyWhiteVPNNodeDelays(subscriptionID string, measured map[string]nodeDelay) model.WhiteVPNNodeList {
	a.nodesMu.Lock()
	defer a.nodesMu.Unlock()
	for i, node := range a.nodes[subscriptionID] {
		delay, ok := measured[node.Name]
		if !ok {
			continue
		}
		a.nodes[subscriptionID][i].DelayMs = delay.delayMs
		a.nodes[subscriptionID][i].DelayOK = delay.ok
		a.nodes[subscriptionID][i].DelayTested = true
	}
	return a.nodeListLocked(subscriptionID)
}

// whiteVPNNodesSnapshot is the parsed catalogue for the connect path, refreshed
// from the subscription it is about to use.
func (a *App) whiteVPNNodesSnapshot(subscriptionID string) []model.WhiteVPNNode {
	a.nodesMu.Lock()
	defer a.nodesMu.Unlock()
	return append([]model.WhiteVPNNode(nil), a.nodes[subscriptionID]...)
}

func (a *App) nodeListLocked(subscriptionID string) model.WhiteVPNNodeList {
	list := model.WhiteVPNNodeList{Nodes: append([]model.WhiteVPNNode(nil), a.nodes[subscriptionID]...)}
	if list.Nodes == nil {
		list.Nodes = []model.WhiteVPNNode{}
	}
	if fetchedAt, ok := a.nodesAt[subscriptionID]; ok {
		list.UpdatedAt = fetchedAt.Format(time.RFC3339)
	}
	return list
}

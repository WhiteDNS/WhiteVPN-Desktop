package main

// The connection chain across subscriptions: node 1 and node 2 can each come
// from any list, and the engine is handed one document holding both. The
// planning — which configs can be which node, and how the two are wired — is
// mihomoconf.PlanChain; this file finds the lists and keeps the setting.

import (
	"context"
	"fmt"
	"slices"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/sessionmanager"
)

// chainSubscription is the document a chained connection is built from.
func (a *App) chainSubscription(ctx context.Context, chain model.ChainSettings) (string, mihomoconf.Chain, error) {
	sources, err := a.chainSources(ctx, chain)
	if err != nil {
		return "", mihomoconf.Chain{}, err
	}
	proxies, plan, err := mihomoconf.PlanChain(sources, chainHopFor(chain.Entry), chainHopFor(chain.Exit))
	if err != nil {
		return "", mihomoconf.Chain{}, err
	}
	body, err := mihomoconf.MergedDocument(proxies)
	if err != nil {
		return "", mihomoconf.Chain{}, err
	}
	return body, plan, nil
}

func chainHopFor(hop model.ChainHop) mihomoconf.ChainHop {
	if hop.Mode == model.ChainHopAutomatic {
		return mihomoconf.ChainHop{Ref: mihomoconf.ChainRef{SubscriptionID: hop.SubscriptionID}}
	}
	if hop.Mode != model.ChainHopFixed {
		return mihomoconf.ChainHop{}
	}
	return mihomoconf.ChainHop{Ref: mihomoconf.ChainRef{SubscriptionID: hop.SubscriptionID, Node: hop.Node}}
}

// chainSources reads the lists a chain draws from: every list when either node
// is Automatic, otherwise only the lists the two fixed configs are in.
//
// A fixed config's list is fetched fresh, the way a single-hop connection's is,
// and failing to read it fails the connection. The rest come from their saved
// copies and are skipped when unreadable: they are only more to choose from.
func (a *App) chainSources(ctx context.Context, chain model.ChainSettings) ([]mihomoconf.ChainSource, error) {
	fixed := map[string]bool{}
	var wanted []subscriptionSource
	everyList := func(hop model.ChainHop) bool { return hop.Mode == model.ChainHopAutomatic && hop.SubscriptionID == "" }
	if everyList(chain.Entry) || everyList(chain.Exit) {
		wanted = a.everySubscriptionSource()
	}
	for _, hop := range []model.ChainHop{chain.Entry, chain.Exit} {
		// A fixed node's list, or the one list an Automatic node is limited to.
		if hop.Mode == model.ChainHopOff || hop.SubscriptionID == "" || fixed[hop.SubscriptionID] {
			continue
		}
		fixed[hop.SubscriptionID] = true
		if !slices.ContainsFunc(wanted, func(s subscriptionSource) bool { return s.id == hop.SubscriptionID }) {
			wanted = append(wanted, subscriptionSource{id: hop.SubscriptionID, name: a.subscriptionDisplayName(hop.SubscriptionID)})
		}
	}

	sources := make([]mihomoconf.ChainSource, 0, len(wanted))
	for _, source := range wanted {
		proxies, err := a.chainSourceProxies(ctx, source.id, fixed[source.id])
		if err != nil {
			if fixed[source.id] {
				return nil, fmt.Errorf("%s could not be read for the chain: %w", source.name, err)
			}
			a.appendRuntimeLog(fmt.Sprintf("chain: skipping %s: %v", source.name, err))
			continue
		}
		sources = append(sources, mihomoconf.ChainSource{ID: source.id, Name: source.name, Proxies: proxies})
	}
	return sources, nil
}

// chainSourceProxies is one list's proxies, without the ones the user hid.
func (a *App) chainSourceProxies(ctx context.Context, id string, fresh bool) ([]mihomoconf.Proxy, error) {
	var body string
	if !fresh && subscriptionIsStorable(id) && a.sourceCredentialError(id) == nil {
		if snapshot, ok := a.lastKnownGoodSubscription(id); ok {
			body = snapshot.Body
		}
	}
	if body == "" {
		fetched, err := a.subscriptionBodyFor(ctx, id)
		if err != nil {
			return nil, err
		}
		body = fetched
	}
	proxies, _, err := mihomoconf.ParseSubscription(body)
	if err != nil {
		return nil, err
	}
	hidden := a.hiddenNodeNames(id)
	return slices.DeleteFunc(proxies, func(proxy mihomoconf.Proxy) bool { return slices.Contains(hidden, proxy.Name()) }), nil
}

// ListChainOptions is everything the chain picker offers for one node, grouped
// by subscription, with the reason any config cannot fill it.
//
// A list never downloaded has nothing to show, so when any list has no saved
// copy every list is fetched first — the phone, before it did this, offered
// only WARP on a fresh install. What still cannot be read is reported as
// Incomplete rather than silently missing.
func (a *App) ListChainOptions(slot string) (model.ChainOptions, error) {
	a.mu.Lock()
	chain := model.NormalizeChainSettings(a.state.WhiteVPN.Chain)
	a.mu.Unlock()
	other := chain.Exit
	if slot == model.ChainSlotExit {
		other = chain.Entry
	}

	sources := a.everySubscriptionSource()
	refresh := slices.ContainsFunc(sources, func(source subscriptionSource) bool {
		if !subscriptionIsStorable(source.id) {
			return false
		}
		_, ok := a.lastKnownGoodSubscription(source.id)
		return !ok
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	options := model.ChainOptions{Groups: []model.ChainOptionGroup{}}
	chainSources := make([]mihomoconf.ChainSource, 0, len(sources))
	for _, source := range sources {
		list, err := a.ListSubscriptionNodes(source.id, refresh)
		if err != nil {
			options.Incomplete = true
		}
		proxies, proxiesErr := a.chainSourceProxies(ctx, source.id, false)
		if proxiesErr != nil {
			options.Incomplete = true
			continue
		}
		chainSource := mihomoconf.ChainSource{ID: source.id, Name: source.name, Proxies: proxies}
		chainSources = append(chainSources, chainSource)
		selectable := mihomoconf.ChainSelectable(chainSource)
		group := model.ChainOptionGroup{SubscriptionID: source.id, Name: source.name,
			UserMade: !model.IsBuiltInSubscription(source.id), Nodes: []model.WhiteVPNNode{}}
		for _, node := range list.Nodes {
			if selectable[node.Name] && !node.Hidden && !node.CredentialRequired {
				group.Nodes = append(group.Nodes, node)
			}
		}
		if len(group.Nodes) > 0 {
			options.Groups = append(options.Groups, group)
		}
	}

	if other.Mode == model.ChainHopFixed {
		issues := mihomoconf.ChainPickerIssues(chainSources, slot == model.ChainSlotEntry, chainHopFor(other))
		for i := range options.Groups {
			group := &options.Groups[i]
			for _, node := range group.Nodes {
				if issue, ok := issues[mihomoconf.ChainRef{SubscriptionID: group.SubscriptionID, Node: node.Name}]; ok {
					if group.Issues == nil {
						group.Issues = map[string]string{}
					}
					group.Issues[node.Name] = string(issue)
				}
			}
		}
	}
	return options, nil
}

// SaveConnectionChain stores the two nodes.
//
// Its own call rather than part of SaveWhiteVPNSettings, because the picker
// that changes it is on the VPN page as well as on the settings page, and a
// settings form saved with an older copy of the chain would undo the pick. A
// running connection follows the change, as on the phone.
func (a *App) SaveConnectionChain(chain model.ChainSettings) (model.AppState, error) {
	chain = model.NormalizeChainSettings(chain)
	a.mu.Lock()
	previous := model.NormalizeChainSettings(a.state.WhiteVPN.Chain)
	a.state.WhiteVPN.Chain = chain
	state, err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		return state, fmt.Errorf("save chain: %w", err)
	}
	if previous != chain && (previous.Active() || chain.Active()) {
		snapshot := a.connectionManager().Snapshot()
		if snapshot.Phase == sessionmanager.Connected && snapshot.Route != nil && snapshot.Route.Kind == "mihomo" {
			return a.connectMihomo(true)
		}
	}
	return state, nil
}

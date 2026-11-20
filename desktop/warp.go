package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/warp"
)

// warpRegisterURL is a variable only so tests can point it at a local server.
var warpRegisterURL = warp.RegisterURL

// WarpSettings is what the WARP editor shows and changes. The keys and
// addresses stay in Go: the interface never needs them.
type WarpSettings struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	Port   int    `json:"port"`
	Noise  bool   `json:"noise"`
}

// AddWarpSubscription registers a WARP device and saves it as a user
// subscription named WARP, holding its YAML inline.
func (a *App) AddWarpSubscription() (model.AppState, error) {
	body, err := a.registerWarp(context.Background())
	if err != nil {
		a.appendRuntimeLog(fmt.Sprintf("WARP registration failed: %v", err))
		return a.GetAppState(), fmt.Errorf("could not create a WARP account")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := uniqueV2RaySubscriptionID(a.state.V2RaySubscriptions)
	a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, model.V2RaySubscription{
		ID:            id,
		Name:          warp.ProxyName,
		Body:          body,
		ImportedCount: 1,
		LastUpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	return a.saveLocked()
}

// registerWarp tries the running connection's mixed port first, then direct,
// as the phone does. Go's HTTP client ignores the system proxy, so in
// proxy-only mode direct would bypass the VPN; in TUN mode both paths end up in
// the tunnel and the order only costs a retry.
func (a *App) registerWarp(ctx context.Context) (string, error) {
	var proxiedErr error
	if proxied, err := a.proxyHTTPClient(); err == nil && proxied != nil {
		client := *proxied
		client.Timeout = warp.Timeout
		body, err := warp.Register(ctx, &client, warpRegisterURL)
		if err == nil {
			return body, nil
		}
		proxiedErr = err
	}
	body, err := warp.Register(ctx, &http.Client{Timeout: warp.Timeout}, warpRegisterURL)
	if err != nil && proxiedErr != nil {
		return "", fmt.Errorf("through the connection: %v; direct: %w", proxiedErr, err)
	}
	return body, err
}

// GetWarpSettings fails for a subscription that is not WARP, which is how the
// interface decides which editor to open.
func (a *App) GetWarpSettings(id string) (WarpSettings, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sub, config, err := a.warpSubscriptionLocked(id)
	if err != nil {
		return WarpSettings{}, err
	}
	return WarpSettings{Name: sub.Name, Server: config.Server, Port: config.Port, Noise: config.Noise}, nil
}

// SaveWarpSettings rebuilds the YAML from the stored keys and addresses,
// changing only the name, server, port and noise.
func (a *App) SaveWarpSettings(id string, settings WarpSettings) (model.AppState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, config, err := a.warpSubscriptionLocked(id)
	if err != nil {
		return a.publicStateLocked(), err
	}
	name, server := strings.TrimSpace(settings.Name), strings.TrimSpace(settings.Server)
	if name == "" || !warp.ValidServer(server) || !warp.ValidPort(settings.Port) {
		return a.publicStateLocked(), fmt.Errorf("check the name, server IP and port")
	}
	config.Server, config.Port, config.Noise = server, settings.Port, settings.Noise
	body, err := config.YAML()
	if err != nil {
		return a.publicStateLocked(), err
	}
	idx := findV2RaySubscriptionIndex(a.state.V2RaySubscriptions, strings.TrimSpace(id))
	a.state.V2RaySubscriptions[idx].Name = name
	a.state.V2RaySubscriptions[idx].Body = body
	a.state.V2RaySubscriptions[idx].LastError = ""
	// The cached nodes were parsed from the old body.
	a.forgetWhiteVPNNodes(a.state.V2RaySubscriptions[idx].ID)
	return a.saveLocked()
}

func (a *App) warpSubscriptionLocked(id string) (model.V2RaySubscription, warp.Config, error) {
	sub, ok := findV2RaySubscription(a.state, strings.TrimSpace(id))
	if !ok {
		return sub, warp.Config{}, fmt.Errorf("subscription not found")
	}
	config, ok := warp.Parse(sub.Body)
	if !ok {
		return sub, warp.Config{}, fmt.Errorf("not a WARP subscription")
	}
	return sub, config, nil
}

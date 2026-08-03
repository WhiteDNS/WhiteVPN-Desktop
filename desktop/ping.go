package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"whitevpn-desktop/internal/model"
)

const proxyPingTarget = "https://www.google.com/generate_204"

func (a *App) PingCloudflare() (model.CloudflarePingResult, error) {
	proxyConfig, err := a.activeProxyConfig()
	if err != nil {
		return model.CloudflarePingResult{Target: proxyPingTarget}, err
	}
	client, err := httpClientThroughProxy(proxyConfig)
	if err != nil {
		return model.CloudflarePingResult{Target: proxyPingTarget, Proxy: proxyConfig.Address}, err
	}
	defer closeHTTPClientIdleConnections(client)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyPingTarget, nil)
	if err != nil {
		return model.CloudflarePingResult{Target: proxyPingTarget, Proxy: proxyConfig.Address}, err
	}
	req.Header.Set("User-Agent", "WhiteDNS-Desktop")

	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return model.CloudflarePingResult{Target: proxyPingTarget, Proxy: proxyConfig.Address}, fmt.Errorf("google generate_204 ping failed through proxy: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	latency := time.Since(started).Milliseconds()
	if resp.StatusCode != http.StatusNoContent {
		return model.CloudflarePingResult{Target: proxyPingTarget, Proxy: proxyConfig.Address, LatencyMs: latency}, fmt.Errorf("google generate_204 returned HTTP %d", resp.StatusCode)
	}

	return model.CloudflarePingResult{
		OK:        true,
		Target:    proxyPingTarget,
		Proxy:     proxyConfig.Address,
		LatencyMs: latency,
		Message:   fmt.Sprintf("Google generate_204 reachable in %d ms", latency),
	}, nil
}

type runtimeProxyConfig struct {
	Address  string
	Protocol string
	Auth     *proxy.Auth
}

func (cfg runtimeProxyConfig) cacheKey() string {
	return cfg.Protocol + "://" + cfg.Address
}

func (a *App) activeSOCKS5Proxy() (string, *proxy.Auth, error) {
	cfg, err := a.activeProxyConfig()
	if err != nil {
		return "", nil, err
	}
	if cfg.Protocol == "http" {
		return "", nil, fmt.Errorf("active proxy is HTTP, not SOCKS")
	}
	return cfg.Address, cfg.Auth, nil
}

func (a *App) activeProxyConfig() (runtimeProxyConfig, error) {
	a.mu.Lock()
	runtime := a.state.Runtime
	settings := selectedSettingsProfile(a.state)
	v2rayActive := activeRuntimeIsV2Ray(a.state, runtime.ActiveConnectionID)
	a.mu.Unlock()

	if runtime.Status != model.RuntimeConnected {
		return runtimeProxyConfig{}, fmt.Errorf("proxy is not connected")
	}
	proxyAddress, err := runtimeSOCKSProxyAddress(runtime)
	if err != nil {
		return runtimeProxyConfig{}, err
	}

	var auth *proxy.Auth
	if !v2rayActive && settings.SOCKS5Authentication {
		auth = &proxy.Auth{User: settings.SOCKSUsername, Password: settings.SOCKSPassword}
	}
	protocol := normalizeRuntimeProxyProtocol(runtime.ProxyProtocol)
	if protocol == "" {
		if !v2rayActive {
			protocol = normalizeRuntimeProxyProtocol(settings.SingBoxInboundType)
		}
		if protocol == "" {
			protocol = "socks"
		}
	}
	return runtimeProxyConfig{Address: proxyAddress, Protocol: protocol, Auth: auth}, nil
}

func activeRuntimeIsV2Ray(state model.AppState, activeConnectionID string) bool {
	activeConnectionID = strings.TrimSpace(activeConnectionID)
	if activeConnectionID == "" {
		return false
	}
	for _, profile := range state.V2RayProfiles {
		if profile.ID == activeConnectionID {
			return true
		}
	}
	return false
}

func runtimeSOCKSProxyAddress(runtime model.RuntimeStatus) (string, error) {
	if runtime.ListenPort <= 0 {
		return "", fmt.Errorf("proxy port is unavailable")
	}
	host := strings.TrimSpace(runtime.LocalProxyIP)
	if host == "" {
		host = strings.TrimSpace(runtime.ListenIP)
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(runtime.ListenPort)), nil
}

func normalizeRuntimeProxyProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http":
		return "http"
	case "socks", "mixed":
		return "socks"
	default:
		return ""
	}
}

func selectedSettingsProfile(state model.AppState) model.SettingsProfile {
	for _, profile := range state.SettingsProfiles {
		if profile.ID == state.SelectedSettingsProfileID {
			return profile
		}
	}
	return model.DefaultSettingsProfile()
}

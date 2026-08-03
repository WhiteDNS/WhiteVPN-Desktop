package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"whitevpn-desktop/internal/model"
)

const proxyCountryLookupURL = "https://www.cloudflare.com/cdn-cgi/trace"

type proxyCountryCacheEntry struct {
	result     model.ProxyCountryLookupResult
	errMessage string
}

func (a *App) LookupProxyCountry() (model.ProxyCountryLookupResult, error) {
	proxyConfig, err := a.activeProxyConfig()
	if err != nil {
		return model.ProxyCountryLookupResult{}, err
	}
	if result, err, ok := a.cachedProxyCountry(proxyConfig.cacheKey()); ok {
		return result, err
	}

	result, err := a.lookupProxyCountry(proxyConfig)
	a.storeProxyCountry(proxyConfig.cacheKey(), result, err)
	return result, err
}

func (a *App) lookupProxyCountry(proxyConfig runtimeProxyConfig) (model.ProxyCountryLookupResult, error) {
	client, err := httpClientThroughProxy(proxyConfig)
	if err != nil {
		return model.ProxyCountryLookupResult{Proxy: proxyConfig.Address}, err
	}
	defer closeHTTPClientIdleConnections(client)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyCountryLookupURL, nil)
	if err != nil {
		return model.ProxyCountryLookupResult{Proxy: proxyConfig.Address}, err
	}
	req.Header.Set("User-Agent", "WhiteDNS-Desktop")

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return model.ProxyCountryLookupResult{Proxy: proxyConfig.Address}, fmt.Errorf("proxy country lookup failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.ProxyCountryLookupResult{Proxy: proxyConfig.Address}, fmt.Errorf("proxy country lookup failed: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return model.ProxyCountryLookupResult{Proxy: proxyConfig.Address}, err
	}
	ip, countryCode := parseCloudflareTrace(raw)
	if countryCode == "" {
		return model.ProxyCountryLookupResult{IP: ip, Proxy: proxyConfig.Address}, fmt.Errorf("proxy country lookup did not return a country")
	}
	message := fmt.Sprintf("Proxy country resolved to %s", countryCode)
	if ip != "" {
		message = fmt.Sprintf("Proxy egress IP %s resolved to %s", ip, countryCode)
	}

	return model.ProxyCountryLookupResult{
		OK:          true,
		IP:          ip,
		CountryCode: countryCode,
		Proxy:       proxyConfig.Address,
		Message:     message,
	}, nil
}

func (a *App) cachedProxyCountry(proxyAddress string) (model.ProxyCountryLookupResult, error, bool) {
	a.proxyCountryMu.Lock()
	defer a.proxyCountryMu.Unlock()
	entry, ok := a.proxyCountryCache[proxyAddress]
	if !ok {
		return model.ProxyCountryLookupResult{}, nil, false
	}
	if entry.errMessage != "" {
		return entry.result, errors.New(entry.errMessage), true
	}
	return entry.result, nil, true
}

func (a *App) storeProxyCountry(proxyAddress string, result model.ProxyCountryLookupResult, err error) {
	a.proxyCountryMu.Lock()
	defer a.proxyCountryMu.Unlock()
	if a.proxyCountryCache == nil {
		a.proxyCountryCache = map[string]proxyCountryCacheEntry{}
	}
	entry := proxyCountryCacheEntry{result: result}
	if err != nil {
		entry.errMessage = err.Error()
	}
	a.proxyCountryCache[proxyAddress] = entry
}

func (a *App) clearProxyCountryCache() {
	a.proxyCountryMu.Lock()
	defer a.proxyCountryMu.Unlock()
	a.proxyCountryCache = map[string]proxyCountryCacheEntry{}
}

func httpClientThroughProxy(proxyConfig runtimeProxyConfig) (*http.Client, error) {
	if proxyConfig.Protocol == "http" {
		proxyURL := &url.URL{Scheme: "http", Host: proxyConfig.Address}
		if proxyConfig.Auth != nil {
			proxyURL.User = url.UserPassword(proxyConfig.Auth.User, proxyConfig.Auth.Password)
		}
		return &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyURL(proxyURL),
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				IdleConnTimeout:       15 * time.Second,
			},
			Timeout: 8 * time.Second,
		}, nil
	}
	return httpClientThroughSOCKS5(proxyConfig.Address, proxyConfig.Auth)
}

func httpClientThroughSOCKS5(proxyAddress string, auth *proxy.Auth) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddress, auth, socks5ForwardDialer{timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext:           socks5DialContext(dialer),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       15 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second}, nil
}

type socks5ForwardDialer struct {
	timeout time.Duration
}

func (d socks5ForwardDialer) Dial(network string, address string) (net.Conn, error) {
	timeout := d.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: timeout}).Dial(network, address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func socks5DialContext(dialer proxy.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		type dialResult struct {
			conn net.Conn
			err  error
		}
		done := make(chan dialResult)
		go func() {
			conn, err := dialer.Dial(network, address)
			if conn != nil && err == nil {
				_ = conn.SetDeadline(time.Time{})
			}
			if conn != nil && err != nil {
				_ = conn.Close()
			}
			select {
			case done <- dialResult{conn: conn, err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
		select {
		case result := <-done:
			return result.conn, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func closeHTTPClientIdleConnections(client *http.Client) {
	if client == nil || client.Transport == nil {
		return
	}
	type idleCloser interface {
		CloseIdleConnections()
	}
	if transport, ok := client.Transport.(idleCloser); ok {
		transport.CloseIdleConnections()
	}
}

func parseCloudflareTrace(raw []byte) (string, string) {
	var ip string
	var countryCode string
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ip":
			ip = strings.TrimSpace(value)
		case "loc":
			countryCode = strings.ToUpper(strings.TrimSpace(value))
		}
	}
	return ip, countryCode
}

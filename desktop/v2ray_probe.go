package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtimemgr "whitevpn-desktop/internal/runtime"
)

// A probe runs a profile in a throwaway xray instance so ping and speed tests
// never disturb whatever the user currently has connected.
type probeRuntimeManager interface {
	StartXray(context.Context, runtimemgr.XrayLaunchConfig) error
	Stop() error
}

const (
	speedTestMaxBytes   = 2 * 1024 * 1024
	probeRuntimeDirName = "profile-test"
)

var speedTestURLs = []string{
	"https://speed.cloudflare.com/__down?bytes=2097152",
	"https://proof.ovh.net/files/1Mb.dat",
}

type speedTestResult struct {
	bytesPerSecond int64
	bytes          int64
	duration       time.Duration
	err            error
}

func downloadSpeedFromURL(ctx context.Context, client *http.Client, endpoint string, maxBytes int64) speedTestResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return speedTestResult{err: err}
	}
	req.Header.Set("Cache-Control", "no-cache")

	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return speedTestResult{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return speedTestResult{err: fmt.Errorf("download speed test returned HTTP %d", resp.StatusCode)}
	}

	bytes, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	duration := time.Since(started)
	result := speedTestResult{
		bytes:    bytes,
		duration: duration,
		err:      copyErr,
	}
	if bytes > 0 && duration > 0 {
		result.bytesPerSecond = int64(float64(bytes) / duration.Seconds())
	}
	if result.bytesPerSecond > 0 {
		result.err = nil
	}
	return result
}

func (a *App) newProbeRuntimeManager(profileID, phase string, callbacks runtimemgr.Callbacks) (probeRuntimeManager, func(), error) {
	runtimeRoot := ""
	if configDir, err := appConfigDir(); err == nil {
		runtimeRoot = filepath.Join(configDir, "runtime", probeRuntimeDirName)
	}
	if runtimeRoot == "" {
		runtimeRoot = filepath.Join(os.TempDir(), "whitevpn-desktop", probeRuntimeDirName)
	}
	if err := os.MkdirAll(runtimeRoot, 0o755); err != nil {
		return nil, func() {}, err
	}
	runtimeDir, err := os.MkdirTemp(runtimeRoot, sanitizeProbePathPart(profileID)+"-"+sanitizeProbePathPart(phase)+"-")
	if err != nil {
		return nil, func() {}, err
	}
	factory := a.runtimeManagerFactory
	if factory == nil {
		factory = func(runtimeDir string, callbacks runtimemgr.Callbacks) probeRuntimeManager {
			return runtimemgr.NewManager(runtimeManagerOptions(runtimeDir), callbacks)
		}
	}
	manager := factory(runtimeDir, callbacks)
	cleanup := func() {
		if manager != nil {
			_ = manager.Stop()
		}
		_ = os.RemoveAll(runtimeDir)
	}
	return manager, cleanup, nil
}

func freeLocalTCPPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func sanitizeProbePathPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "probe"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

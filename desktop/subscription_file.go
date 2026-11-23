package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"whitevpn-desktop/internal/model"
)

func (a *App) ImportSubscriptionFile(title string) (*model.AppState, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("file picker is unavailable")
	}
	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{Title: title})
	if err != nil || path == "" {
		return nil, err
	}
	return a.importSubscriptionFile(path)
}

func (a *App) ImportSubscriptionClipboard() (*model.AppState, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("clipboard is unavailable")
	}
	text, err := wailsruntime.ClipboardGetText(a.ctx)
	if err != nil {
		return nil, fmt.Errorf("could not read the clipboard")
	}
	return a.importLocalSubscription("", text)
}

func (a *App) importSubscriptionFile(path string) (*model.AppState, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > v2raySubscriptionMaxBytes {
		return nil, fmt.Errorf("choose a configuration file up to 2 MB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open the configuration file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, v2raySubscriptionMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("could not read the configuration file")
	}
	name := strings.TrimSpace(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	return a.importLocalSubscription(name, string(raw))
}

func (a *App) importLocalSubscription(name, text string) (*model.AppState, error) {
	if len(text) > v2raySubscriptionMaxBytes || !utf8.ValidString(text) {
		return nil, fmt.Errorf("choose a readable UTF-8 configuration up to 2 MB")
	}
	body := strings.TrimSpace(strings.TrimPrefix(text, "\uFEFF"))
	nodes, err := whiteVPNNodesFromSubscription(body)
	if err != nil {
		return nil, fmt.Errorf("the configuration contains no supported connections")
	}
	if name == "" {
		name = "Imported configuration"
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	previous := a.state
	a.state.V2RaySubscriptions = append(a.state.V2RaySubscriptions, model.V2RaySubscription{
		ID:            uniqueV2RaySubscriptionID(a.state.V2RaySubscriptions),
		Name:          name,
		Body:          body,
		LocalConfig:   true,
		ImportedCount: len(nodes),
		LastUpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	state, err := a.saveLocked()
	if err != nil {
		a.state = previous
		return nil, err
	}
	return &state, nil
}

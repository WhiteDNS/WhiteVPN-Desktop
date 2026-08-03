package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SaveRuntimeLogs(rawText string) (string, error) {
	text := normalizeRuntimeLogExport(rawText)
	if text == "" {
		return "", fmt.Errorf("no logs to save")
	}
	if a.ctx == nil {
		return "", fmt.Errorf("file picker is unavailable")
	}

	path, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:           "Save runtime logs",
		DefaultFilename: defaultRuntimeLogFilename(time.Now()),
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Log files (*.log)", Pattern: "*.log"},
			{DisplayName: "Text files (*.txt)", Pattern: "*.txt"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func normalizeRuntimeLogExport(rawText string) string {
	text := strings.TrimSpace(rawText)
	if text == "" {
		return ""
	}
	return text + "\n"
}

func defaultRuntimeLogFilename(now time.Time) string {
	return "whitedns-runtime-logs-" + now.Format("20060102-150405") + ".log"
}

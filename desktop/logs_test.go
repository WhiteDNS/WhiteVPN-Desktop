package main

import (
	"testing"
	"time"
)

func TestNormalizeRuntimeLogExport(t *testing.T) {
	if got := normalizeRuntimeLogExport("  \n\t "); got != "" {
		t.Fatalf("expected empty export text, got %q", got)
	}
	if got := normalizeRuntimeLogExport("line one\nline two"); got != "line one\nline two\n" {
		t.Fatalf("unexpected export text: %q", got)
	}
}

func TestDefaultRuntimeLogFilename(t *testing.T) {
	now := time.Date(2026, 5, 26, 14, 30, 15, 0, time.UTC)
	if got := defaultRuntimeLogFilename(now); got != "whitedns-runtime-logs-20260526-143015.log" {
		t.Fatalf("unexpected filename: %q", got)
	}
}

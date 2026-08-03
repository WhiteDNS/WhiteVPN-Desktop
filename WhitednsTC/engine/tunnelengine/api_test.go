package tunnelengine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestScoreRejectsOpenPortOnlyAsFalsePositive(t *testing.T) {
	res := ScanResult{
		TCP: TCPResult{Success: true, Consistency: 1, Attempts: []AttemptMetric{{Success: true, DurationMs: 20}, {Success: true, DurationMs: 21}, {Success: true, DurationMs: 22}}},
	}
	res.Metrics = computeMetrics(res)
	scored := score(res)
	if !scored.FalsePositive || scored.Classification != "False Positive" {
		t.Fatalf("expected open-port-only result to be false positive, got %+v", scored)
	}
}

func TestScanEndpointRejectsInvalidEndpoint(t *testing.T) {
	out := ScanEndpoint(`{"host":"","port":443}`)
	var res ScanResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Score.Grade != "F" {
		t.Fatalf("expected F for invalid endpoint, got %s", res.Score.Grade)
	}
}

func TestScanBatchWithContextReportsProgress(t *testing.T) {
	req := BatchRequest{
		Endpoints: []ScanRequest{
			{Host: "", Port: 443},
			{Host: "example.com", Port: 0},
		},
		AdaptiveLimit: 2,
	}
	var callbacks int
	results, err := ScanBatchWithContext(context.Background(), req, func(_ int, _ ScanResult) {
		callbacks++
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || callbacks != 2 {
		t.Fatalf("expected 2 results and callbacks, got results=%d callbacks=%d", len(results), callbacks)
	}
}

func TestScanBatchWithContextHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanBatchWithContext(ctx, BatchRequest{Endpoints: []ScanRequest{{Host: "example.com", Port: 443}}}, nil)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestClassifyErrDetectsSocketPressure(t *testing.T) {
	if got := classifyErr(errors.New("connectex: Only one usage of each socket address is normally permitted")); got != "socket_pressure" {
		t.Fatalf("expected socket_pressure, got %q", got)
	}
}

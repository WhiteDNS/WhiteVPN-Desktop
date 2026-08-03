//go:build darwin

package traffic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseNettopCSVFindsLatestPIDRow(t *testing.T) {
	raw := []byte(`time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
13:12:59.736791,other.111,,,100,200,0,0,0,,,,,,,,,,,,
13:12:59.736792,masterdns-clien.5748,,,4245847,1465334,0,0,0,,,,,,,,,,,,
time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
13:13:00.741512,masterdns-clien.5748,,,4246000,1466000,0,0,0,,,,,,,,,,,,
`)

	counters, ok, err := ParseNettopCSV(raw, 5748)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected matching nettop row")
	}
	if counters.RXBytes != 4246000 || counters.TXBytes != 1466000 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
}

func TestParseNettopCSVReturnsNoSampleWhenPIDIsMissing(t *testing.T) {
	raw := []byte(`time,,interface,state,bytes_in,bytes_out,
13:12:59.736791,other.111,,,100,200,
`)

	_, ok, err := ParseNettopCSV(raw, 5748)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no matching sample")
	}
}

func TestNettopSamplerTreatsTimeoutAsNoSample(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "slow-nettop")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nsleep 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := NettopSampler{Command: scriptPath, Timeout: 20 * time.Millisecond}.Sample(context.Background(), 123)
	if !errors.Is(err, ErrNoSample) {
		t.Fatalf("expected ErrNoSample for timed out nettop, got %v", err)
	}
}

func TestNettopWasKilled(t *testing.T) {
	if !nettopWasKilled(errors.New("signal: killed")) {
		t.Fatal("expected signal killed error to be recognized")
	}
	if nettopWasKilled(errors.New("exit status 1")) {
		t.Fatal("did not expect generic command error to be recognized as killed")
	}
}

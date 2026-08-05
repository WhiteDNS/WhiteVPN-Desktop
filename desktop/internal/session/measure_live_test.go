package session

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

// A measuring engine that starts is the whole claim, and it is not one unit
// tests can make: the config has to be written where the core looks for it, and
// only the core knows where that is. This starts a real one.
//
//	WHITEVPN_MEASURE_LIVE=1 WHITEVPN_MIHOMO_BIN=../../cores/mihomo-windows-amd64.exe \
//	  go test ./internal/session -run LiveMeasurer -v
func TestLiveMeasurerStartsAndMeasures(t *testing.T) {
	if os.Getenv("WHITEVPN_MEASURE_LIVE") == "" {
		t.Skip("set WHITEVPN_MEASURE_LIVE=1 to run against a real engine")
	}
	corePath := strings.TrimSpace(os.Getenv("WHITEVPN_MIHOMO_BIN"))
	if corePath == "" {
		t.Skip("set WHITEVPN_MIHOMO_BIN to the engine binary")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	measurer, err := StartMeasurer(ctx, MeasureOptions{
		CorePath: corePath,
		HomeDir:  t.TempDir(),
		// Plain nodes: the shared fixture carries a made-up REALITY key that a
		// real engine rejects, and this test is about the engine starting.
		Subscription: strings.Join([]string{
			"trojan://password@a.example.com:443?sni=a.example.com#Alpha",
			"trojan://password@b.example.com:443?sni=b.example.com#Beta",
		}, "\n"),
		PipeSecurityDescriptor: "D:P(A;;GA;;;WD)",
	})
	if err != nil {
		t.Fatalf("the measuring engine did not start: %v", err)
	}
	defer measurer.Close()

	if len(measurer.Names()) == 0 {
		t.Fatal("expected the measuring engine to hold the subscription's nodes")
	}

	// The nodes in sampleLinks are made up, so the measurement will fail. That
	// it fails as a measurement rather than as a broken engine is the point.
	_, err = measurer.Delay(ctx, measurer.Names()[0], mihomoconf.DelayTestURL, 3*time.Second)
	if err != nil && strings.Contains(err.Error(), "config") {
		t.Fatalf("the engine rejected its configuration: %v", err)
	}
}

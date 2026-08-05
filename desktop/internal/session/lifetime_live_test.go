package session

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

// The context that lets a user cancel a connect must not also decide how long
// the connection lives.
//
// It did. Spawn used exec.CommandContext, so the core was killed the moment
// that context was cancelled — which `defer cancel()` does the instant the
// connect function returns. Every proxy-mode connection died about a second
// after reporting success, while TUN was untouched because its core is started
// through ShellExecuteExW, which no context can reach.
//
// This test connects under a context, cancels it, and then asks the connection
// to carry a request. Under the old behaviour the engine is gone by then.
func TestLiveConnectionOutlivesItsConnectContext(t *testing.T) {
	if os.Getenv("WHITEVPN_MEASURE_LIVE") == "" {
		t.Skip("set WHITEVPN_MEASURE_LIVE=1 to run against a real engine")
	}
	corePath := strings.TrimSpace(os.Getenv("WHITEVPN_MIHOMO_BIN"))
	subscriptionPath := strings.TrimSpace(os.Getenv("WHITEVPN_PROBE_SUB"))
	if corePath == "" || subscriptionPath == "" {
		t.Skip("set WHITEVPN_MIHOMO_BIN and WHITEVPN_PROBE_SUB")
	}
	subscription, err := os.ReadFile(subscriptionPath)
	if err != nil {
		t.Fatal(err)
	}

	mixedPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	controlPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}

	// Exactly the shape the app uses: a cancellable context, cancelled as soon
	// as the connecting function is done with it.
	connectCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	current, err := Connect(connectCtx, Options{
		CorePath:               corePath,
		HomeDir:                t.TempDir(),
		Subscription:           string(subscription),
		MixedPort:              mixedPort,
		ControlPort:            controlPort,
		Tun:                    mihomoconf.TunOptions{Enabled: false},
		PipeSecurityDescriptor: "D:P(A;;GA;;;WD)",
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer current.Close()
	cancel()

	// A moment for a kill to land, so a pass means the engine survived rather
	// than that the check was too quick.
	time.Sleep(2 * time.Second)

	if !current.Healthy(context.Background()) {
		t.Fatal("the connection stopped carrying traffic once its connect context was cancelled")
	}
	if _, err := current.Recover(context.Background(), 1); err != nil && strings.Contains(err.Error(), "connection is closed") {
		t.Fatalf("the engine's control channel died with its connect context: %v", err)
	}
}

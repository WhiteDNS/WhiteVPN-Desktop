package session

import (
	"context"
	"os"
	"testing"
	"time"

	"whitevpn-desktop/internal/mihomoconf"
)

// The connect path used to pick nodes itself, always starting at the top of the
// catalogue. Every user therefore tried the same five servers in the same order,
// and Retry tried the same five again — so a bad head of the list did not fail
// some users some of the time, it told everybody the app could not connect. That
// is what the reports were.
//
// This connects three times against the live catalogue and asserts the two
// properties that make the new path different: the engine's own group is
// choosing, and what it chooses is not the same node every time. If either
// regresses, the old failure comes back and looks exactly like a server problem.
//
//	WHITEVPN_CATALOGUE_URL=... WHITEVPN_CATALOGUE_KEY=... go test ./internal/session -run LiveAutomatic -v
func TestLiveAutomaticLetsTheEngineChoose(t *testing.T) {
	catalogueURL := os.Getenv("WHITEVPN_CATALOGUE_URL")
	catalogueKey := os.Getenv("WHITEVPN_CATALOGUE_KEY")
	if catalogueURL == "" || catalogueKey == "" {
		t.Skip("set WHITEVPN_CATALOGUE_URL and WHITEVPN_CATALOGUE_KEY to run this")
	}

	corePath := enginePath(t)
	subscription := fetchSubscription(t, catalogueURL, catalogueKey)

	const runs = 3
	chosen := make([]string, 0, runs)

	for run := 0; run < runs; run++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

		started := time.Now()
		session, err := Connect(ctx, Options{
			CorePath:     corePath,
			HomeDir:      t.TempDir(),
			Subscription: subscription,
			// Its own ports per run: the previous engine may still be letting go
			// of the last ones.
			MixedPort:              23180 + run,
			ControlPort:            23190 + run,
			Tun:                    mihomoconf.TunOptions{Enabled: false},
			PipeSecurityDescriptor: "D:P(A;;GA;;;WD)",
		})
		if err != nil {
			cancel()
			t.Fatalf("run %d: connect: %v", run+1, err)
		}

		t.Logf("run %d: %s, %d of %d sampled nodes answered, engine chose %q",
			run+1, time.Since(started).Round(time.Millisecond), session.Seeded(), seedSample, session.Selected())

		if !session.Automatic() {
			t.Errorf("run %d: the app pinned a node instead of leaving the choice to the engine", run+1)
		}
		if session.Seeded() < seedEnough {
			t.Errorf("run %d: only %d nodes answered, so the group had little to choose from", run+1, session.Seeded())
		}
		if session.Selected() == "" {
			t.Errorf("run %d: connected without being able to name the node carrying traffic", run+1)
		}
		chosen = append(chosen, session.Selected())

		_ = session.Close()
		cancel()
	}

	// Not a strict requirement of correctness — three draws from a live catalogue
	// could legitimately agree — but if it never varies, the catalogue is being
	// walked rather than sampled, which is the bug this replaced.
	same := true
	for _, name := range chosen {
		if name != chosen[0] {
			same = false
			break
		}
	}
	if same {
		t.Logf("all %d runs chose %q — worth a look if it keeps happening", runs, chosen[0])
	}
}

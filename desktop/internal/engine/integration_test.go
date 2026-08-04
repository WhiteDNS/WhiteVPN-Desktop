package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// corePath finds a built engine binary, or skips. The binary is not committed —
// `make mihomo-core` produces it — so this test runs where someone has built the
// engine and quietly stands aside where they have not.
func corePath(t *testing.T) string {
	t.Helper()
	name := "mihomo-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path, err := filepath.Abs(filepath.Join("..", "..", "cores", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("engine binary not built (%s); run `make mihomo-core`", name)
	}
	return path
}

// spawnReal starts the real core. The pipe ACL is widened because tests run
// unelevated, whereas in production the core is elevated and the default
// SYSTEM/Administrators restriction is what we want.
func spawnReal(t *testing.T) *Process {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	proc, err := Spawn(ctx, SpawnOptions{
		CorePath:           corePath(t),
		WorkingDir:         t.TempDir(),
		SecurityDescriptor: "D:P(A;;GA;;;WD)",
		ConnectTimeout:     20 * time.Second,
	})
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() { _ = proc.Stop(context.Background()) })
	return proc
}

// The point of this test is the encoding. Every action carries `data` in the
// shape its handler asserts on, and getting it wrong does not produce a tidy
// error — the core panics inside the handler and answers with an internal
// failure. A fake core cannot catch that; only the real one can.
func TestRealCoreAcceptsOurActionEncoding(t *testing.T) {
	proc := spawnReal(t)
	home := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proc.Init(ctx, home, 36); err != nil {
		t.Fatalf("initClash rejected our encoding: %v", err)
	}

	// getTraffic is the odd one out: it asserts on a bare bool rather than a JSON
	// string, so it fails loudly if everything is stringified uniformly.
	if _, err := proc.Traffic(ctx, false); err != nil {
		t.Fatalf("getTraffic rejected our encoding: %v", err)
	}
	if _, err := proc.TotalTraffic(ctx, false); err != nil {
		t.Fatalf("getTotalTraffic rejected our encoding: %v", err)
	}
}

// A method the core does not implement is dropped without a reply. This is not
// hypothetical: it is how this core behaves, and it is the reason every call
// carries a deadline.
func TestRealCoreLeavesUnknownMethodsUnanswered(t *testing.T) {
	proc := spawnReal(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := proc.invoke(ctx, "whitevpn.noSuchMethod", nil)
	if !errors.Is(err, ErrNoReply) {
		t.Fatalf("expected ErrNoReply from an unimplemented method, got %v", err)
	}
}

// Spawning must fail promptly and clearly when handed something that is not the
// core, rather than waiting out the full connect timeout.
func TestSpawnFailsFastWhenTheCoreCannotRun(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-a-core.exe")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := Spawn(ctx, SpawnOptions{
		CorePath:           missing,
		WorkingDir:         t.TempDir(),
		SecurityDescriptor: "D:P(A;;GA;;;WD)",
		ConnectTimeout:     15 * time.Second,
	})
	if err == nil {
		t.Fatal("expected spawning a non-existent core to fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s to report a core that cannot start", elapsed)
	}
}

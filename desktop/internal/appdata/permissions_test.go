package appdata

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureAppDataWritableSkipsRepairWhenWritable(t *testing.T) {
	runner := &fakeRunner{}
	err := EnsureAppDataWritableWithOptions(context.Background(), filepath.Join(t.TempDir(), "WhiteVPN Desktop"), Options{
		Platform: "darwin",
		Runner:   runner.run,
		Probe:    func(string) error { return nil },
		UserID:   "501",
		GroupID:  "20",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no elevated repair command, got %#v", runner.commandLines())
	}
}

func TestEnsureAppDataWritableRepairsDarwinWithAdministratorPrompt(t *testing.T) {
	runner := &fakeRunner{}
	dir := filepath.Join(t.TempDir(), "WhiteVPN Desktop")

	err := EnsureAppDataWritableWithOptions(context.Background(), dir, Options{
		Platform: "darwin",
		Runner:   runner.run,
		Probe:    probeSequence(fs.ErrPermission, nil),
		UserID:   "501",
		GroupID:  "20",
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(runner.commandLines(), "\n")
	for _, want := range []string{"osascript -e", "with administrator privileges", "chown -R '501:20'", "chmod -R u+rwX", shellQuote(dir)} {
		if !strings.Contains(lines, want) {
			t.Fatalf("expected macOS repair command to contain %q, got:\n%s", want, lines)
		}
	}
}

func TestEnsureAppDataWritableRepairsLinuxWithPkexec(t *testing.T) {
	runner := &fakeRunner{}
	dir := filepath.Join(t.TempDir(), "WhiteVPN Desktop")

	err := EnsureAppDataWritableWithOptions(context.Background(), dir, Options{
		Platform: "linux",
		Runner:   runner.run,
		Probe:    probeSequence(fs.ErrPermission, nil),
		UserID:   "1000",
		GroupID:  "1000",
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(runner.commandLines(), "\n")
	for _, want := range []string{"pkexec sh -c", "chown -R '1000:1000'", "chmod -R u+rwX", shellQuote(dir)} {
		if !strings.Contains(lines, want) {
			t.Fatalf("expected Linux repair command to contain %q, got:\n%s", want, lines)
		}
	}
}

func TestEnsureAppDataWritableReportsMissingPkexec(t *testing.T) {
	runner := &fakeRunner{err: exec.ErrNotFound}
	dir := filepath.Join(t.TempDir(), "WhiteVPN Desktop")

	err := EnsureAppDataWritableWithOptions(context.Background(), dir, Options{
		Platform: "linux",
		Runner:   runner.run,
		Probe:    probeSequence(fs.ErrPermission),
		UserID:   "1000",
		GroupID:  "1000",
	})
	if err == nil || !strings.Contains(err.Error(), "pkexec is required") {
		t.Fatalf("expected missing pkexec error, got %v", err)
	}
}

func TestEnsureAppDataWritableRepairsWindowsWithUACAndSID(t *testing.T) {
	runner := &fakeRunner{}
	dir := filepath.Join(t.TempDir(), "WhiteVPN Desktop")

	err := EnsureAppDataWritableWithOptions(context.Background(), dir, Options{
		Platform: "windows",
		Runner:   runner.run,
		Probe:    probeSequence(errors.New("Access is denied."), nil),
		UserSID:  "S-1-5-21-1000",
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(runner.commandLines(), "\n")
	for _, want := range []string{"powershell -NoProfile -Command", "Start-Process", "-Verb RunAs", "icacls", "*S-1-5-21-1000:(OI)(CI)F"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("expected Windows repair command to contain %q, got:\n%s", want, lines)
		}
	}
}

func TestEnsureAppDataWritableRefusesNonWhiteDNSDirectory(t *testing.T) {
	runner := &fakeRunner{}
	err := EnsureAppDataWritableWithOptions(context.Background(), filepath.Join(t.TempDir(), "Other App"), Options{
		Platform: "darwin",
		Runner:   runner.run,
		Probe:    probeSequence(fs.ErrPermission),
		UserID:   "501",
		GroupID:  "20",
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to repair non-WhiteDNS data directory") {
		t.Fatalf("expected refusal error, got %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no command for invalid directory, got %#v", runner.commandLines())
	}
}

func TestEnsureAppDataWritableReportsStillUnwritableAfterRepair(t *testing.T) {
	runner := &fakeRunner{}
	dir := filepath.Join(t.TempDir(), "WhiteVPN Desktop")

	err := EnsureAppDataWritableWithOptions(context.Background(), dir, Options{
		Platform: "darwin",
		Runner:   runner.run,
		Probe:    probeSequence(fs.ErrPermission, fs.ErrPermission),
		UserID:   "501",
		GroupID:  "20",
	})
	if err == nil || !strings.Contains(err.Error(), "repair completed but the directory is still not writable") {
		t.Fatalf("expected post-repair writability error, got %v", err)
	}
}

type fakeRunner struct {
	calls []runnerCall
	err   error
}

type runnerCall struct {
	name string
	args []string
}

func (r *fakeRunner) run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, runnerCall{name: name, args: append([]string(nil), args...)})
	return "", r.err
}

func (r *fakeRunner) commandLines() []string {
	lines := make([]string, 0, len(r.calls))
	for _, call := range r.calls {
		lines = append(lines, strings.TrimSpace(call.name+" "+strings.Join(call.args, " ")))
	}
	return lines
}

func probeSequence(errs ...error) WriteProbe {
	idx := 0
	return func(string) error {
		if idx >= len(errs) {
			return nil
		}
		err := errs[idx]
		idx++
		return err
	}
}

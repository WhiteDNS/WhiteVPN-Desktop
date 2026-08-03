package appdata

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
)

type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)
type WriteProbe func(dir string) error

type Options struct {
	Platform string
	Runner   CommandRunner
	Probe    WriteProbe
	UserID   string
	GroupID  string
	UserSID  string
}

type userIdentity struct {
	uid string
	gid string
	sid string
}

func EnsureAppDataWritable(ctx context.Context, dir string) error {
	return EnsureAppDataWritableWithOptions(ctx, dir, Options{})
}

func EnsureAppDataWritableWithOptions(ctx context.Context, dir string, options Options) error {
	clean, err := validateAppDataDir(dir)
	if err != nil {
		return err
	}
	probe := options.Probe
	if probe == nil {
		probe = defaultWriteProbe
	}
	if err := probe(clean); err == nil {
		return nil
	} else if !isPermissionError(err) {
		return fmt.Errorf("WhiteDNS Desktop data directory %q is not writable: %w", clean, err)
	} else {
		if repairErr := repairAppDataPermissions(ctx, clean, options); repairErr != nil {
			return fmt.Errorf("WhiteDNS Desktop data directory %q is not writable and automatic repair failed: %w (initial write error: %v)", clean, repairErr, err)
		}
	}
	if err := probe(clean); err != nil {
		return fmt.Errorf("WhiteDNS Desktop data directory %q repair completed but the directory is still not writable: %w", clean, err)
	}
	return nil
}

func validateAppDataDir(dir string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(dir))
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return "", fmt.Errorf("invalid WhiteDNS Desktop data directory %q", dir)
	}
	if filepath.Base(clean) != "WhiteDNS Desktop" {
		return "", fmt.Errorf("refusing to repair non-WhiteDNS data directory %q", dir)
	}
	if info, err := os.Lstat(clean); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to repair symlinked WhiteDNS data directory %q", dir)
	}
	return clean, nil
}

func defaultWriteProbe(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := probeWritableDir(dir); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() || path == dir {
			return nil
		}
		return probeWritableDir(path)
	})
}

func probeWritableDir(dir string) error {
	file, err := os.CreateTemp(dir, ".wd-permission-check-*")
	if err != nil {
		return err
	}
	name := file.Name()
	closeErr := file.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

func repairAppDataPermissions(ctx context.Context, dir string, options Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runner := options.Runner
	if runner == nil {
		runner = defaultCommandRunner
	}
	platform := strings.TrimSpace(options.Platform)
	if platform == "" {
		platform = goruntime.GOOS
	}
	identity, err := resolveUserIdentity(options, platform)
	if err != nil {
		return err
	}
	switch platform {
	case "darwin":
		return repairDarwin(ctx, runner, dir, identity)
	case "linux":
		return repairLinux(ctx, runner, dir, identity)
	case "windows":
		return repairWindows(ctx, runner, dir, identity)
	default:
		return fmt.Errorf("automatic app data permission repair is unsupported on %s", platform)
	}
}

func resolveUserIdentity(options Options, platform string) (userIdentity, error) {
	identity := userIdentity{
		uid: strings.TrimSpace(options.UserID),
		gid: strings.TrimSpace(options.GroupID),
		sid: strings.TrimSpace(options.UserSID),
	}
	if platform == "windows" && identity.sid != "" {
		return identity, nil
	}
	if platform != "windows" && identity.uid != "" && identity.gid != "" {
		return identity, nil
	}
	current, err := user.Current()
	if err != nil {
		return identity, fmt.Errorf("failed to determine current user for app data repair: %w", err)
	}
	if identity.uid == "" {
		identity.uid = strings.TrimSpace(current.Uid)
	}
	if identity.gid == "" {
		identity.gid = strings.TrimSpace(current.Gid)
	}
	if identity.sid == "" {
		identity.sid = strings.TrimSpace(current.Uid)
	}
	if identity.uid == "" {
		return identity, errors.New("failed to determine current user ID for app data repair")
	}
	return identity, nil
}

func repairDarwin(ctx context.Context, runner CommandRunner, dir string, identity userIdentity) error {
	if identity.gid == "" {
		return errors.New("failed to determine current group ID for macOS app data repair")
	}
	script := "mkdir -p " + shellQuote(dir) +
		" && chown -R " + shellQuote(identity.uid+":"+identity.gid) + " " + shellQuote(dir) +
		" && chmod -R u+rwX " + shellQuote(dir)
	output, err := runner(ctx, "osascript", "-e", "do shell script "+strconv.Quote(script)+" with administrator privileges")
	return commandError("macOS administrator permission repair", output, err)
}

func repairLinux(ctx context.Context, runner CommandRunner, dir string, identity userIdentity) error {
	if identity.gid == "" {
		return errors.New("failed to determine current group ID for Linux app data repair")
	}
	script := "mkdir -p " + shellQuote(dir) +
		" && chown -R " + shellQuote(identity.uid+":"+identity.gid) + " " + shellQuote(dir) +
		" && chmod -R u+rwX " + shellQuote(dir)
	output, err := runner(ctx, "pkexec", "sh", "-c", script)
	if err != nil && commandMissing(output, err) {
		return fmt.Errorf("pkexec is required for Linux app data permission repair: %w", err)
	}
	return commandError("Linux administrator permission repair", output, err)
}

func repairWindows(ctx context.Context, runner CommandRunner, dir string, identity userIdentity) error {
	if identity.sid == "" {
		return errors.New("failed to determine current Windows user SID for app data repair")
	}
	grant := "*" + identity.sid + ":(OI)(CI)F"
	inner := "$ErrorActionPreference='Stop'; " +
		"New-Item -ItemType Directory -Force -LiteralPath " + powershellSingleQuote(dir) + " | Out-Null; " +
		"& icacls " + powershellSingleQuote(dir) + " /grant " + powershellSingleQuote(grant) + " /T /C | Out-Null; " +
		"if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
	outer := "$p=Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command'," +
		powershellSingleQuote(inner) + ") -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode"
	output, err := runner(ctx, "powershell", "-NoProfile", "-Command", outer)
	return commandError("Windows administrator permission repair", output, err)
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsoleWindow(cmd)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func commandError(action string, output string, err error) error {
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(output)
	if text == "" {
		return fmt.Errorf("%s failed: %w", action, err)
	}
	return fmt.Errorf("%s failed: %w: %s", action, err, text)
}

func commandMissing(output string, err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	text := strings.ToLower(output + " " + err.Error())
	return strings.Contains(text, "executable file not found") ||
		strings.Contains(text, "no such file or directory") ||
		strings.Contains(text, "command not found")
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) || errors.Is(err, os.ErrPermission) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "permission denied") ||
		strings.Contains(text, "operation not permitted") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "access denied")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

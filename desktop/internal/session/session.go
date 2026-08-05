package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitevpn-desktop/internal/engine"
	"whitevpn-desktop/internal/mihomoconf"
)

// Options describes one connection attempt.
type Options struct {
	// CorePath is the engine executable; HomeDir is where it runs and where its
	// config is written.
	CorePath string
	HomeDir  string

	// Subscription is the decrypted subscription body: share links, or mihomo
	// YAML. Which one it is does not have to be stated; it is detected.
	Subscription string

	MixedPort   int
	ControlPort int

	DNSPrivacy  mihomoconf.DNSPrivacyMode
	DoHURL      string
	DoTEndpoint string

	Tun mihomoconf.TunOptions

	// MaxAttempts caps how many nodes are tried before giving up. A subscription
	// holds hundreds and most of a bad run fails the same way, so working through
	// all of them would keep a user waiting for an outcome that is not coming.
	MaxAttempts int

	// Prefer restricts and orders the nodes this session may try, by name. Empty
	// means the whole subscription in its own order, which is what the dashboard
	// calls Automatic.
	//
	// The nodes not named here stay in the configuration — the group still holds
	// everything, so a later selection needs no reconnect — they are simply not
	// what this attempt reaches for. Names that no longer exist are dropped, and
	// a Prefer that leaves nothing is an error rather than a silent fallback to
	// the whole list: a user who asked for one country must not be connected to
	// another without being told.
	Prefer []string

	// FrontingIP reaches every eligible node through this address instead of the
	// one its name resolves to, while still presenting the name. Empty means the
	// nodes are reached directly.
	FrontingIP string

	// CoreStdout and CoreStderr receive the engine's own output. Some startup
	// failures are only ever printed there.
	CoreStdout io.Writer
	CoreStderr io.Writer

	// PipeSecurityDescriptor widens the Windows control channel for unelevated
	// development. Leave empty in production.
	PipeSecurityDescriptor string
}

// Session is a connected engine.
type Session struct {
	process    *engine.Process
	mixedPort  int
	configPath string
	proxyCount int
	healthCode int
	candidates []string
	selected   string
}

// Selected is the node currently carrying traffic.
func (s *Session) Selected() string { return s.selected }

// MixedPort is where the session's local proxy listens.
func (s *Session) MixedPort() int { return s.mixedPort }

// ProxyCount is how many nodes the subscription yielded.
func (s *Session) ProxyCount() int { return s.proxyCount }

// HealthStatus is the status code that proved the connection works.
func (s *Session) HealthStatus() int { return s.healthCode }

// Engine exposes the running engine for proxy selection and delay tests.
func (s *Session) Engine() *engine.Process { return s.process }

// Connect prepares a configuration, starts the engine, and returns only once a
// real request has completed through it.
//
// Reaching the end of this function is the definition of connected. Every
// earlier step can report success while the connection does not work: the engine
// answers startListener with success even when it could not create a tunnel, and
// a config it accepts may still name a server that refuses to talk.
func Connect(ctx context.Context, opts Options) (*Session, error) {
	opts = withDefaults(opts)

	document, candidates, err := PrepareConfig(opts)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opts.HomeDir, 0o755); err != nil {
		return nil, fmt.Errorf("session: prepare home directory: %w", err)
	}
	configPath := filepath.Join(opts.HomeDir, "config.yaml")
	// 0600: the config carries every credential in the subscription.
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		return nil, fmt.Errorf("session: write config: %w", err)
	}

	process, err := engine.Spawn(ctx, engine.SpawnOptions{
		CorePath:       opts.CorePath,
		WorkingDir:     opts.HomeDir,
		ConnectTimeout: 20 * time.Second,
		Stdout:         opts.CoreStdout,
		Stderr:         opts.CoreStderr,
		// A tunnel adapter cannot be created without Administrator, so asking for
		// it follows the tunnel setting rather than being a separate choice.
		Elevated:           opts.Tun.Enabled,
		SecurityDescriptor: opts.PipeSecurityDescriptor,
	})
	if err != nil {
		return nil, err
	}

	session := &Session{
		process:    process,
		mixedPort:  opts.MixedPort,
		configPath: configPath,
		proxyCount: len(candidates),
		candidates: candidates,
	}
	// Any failure from here on leaves an engine running, so it has to be stopped
	// rather than abandoned: an abandoned one keeps its listeners, and on the TUN
	// path its adapter and routes as well.
	if err := session.start(ctx, opts); err != nil {
		_ = session.Close()
		return nil, err
	}
	return session, nil
}

func (s *Session) start(ctx context.Context, opts Options) error {
	setupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := s.process.Init(setupCtx, opts.HomeDir, 36); err != nil {
		return fmt.Errorf("session: initialise engine: %w", err)
	}
	if err := s.process.ValidateConfig(setupCtx, s.configPath); err != nil {
		// Only catches configs the engine cannot parse, but that is worth
		// knowing before starting rather than after.
		return fmt.Errorf("session: %w", err)
	}
	if err := s.process.SetupConfig(setupCtx, map[string]string{}, healthURLs[0]); err != nil {
		return fmt.Errorf("session: apply config: %w", err)
	}
	if err := s.process.StartListener(setupCtx); err != nil {
		return fmt.Errorf("session: start listener: %w", err)
	}

	probe := func(probeCtx context.Context) int { return probeStatus(probeCtx, opts.MixedPort) }

	// A node has to be chosen explicitly, as the phone app does. Leaving the
	// selection to the url-test group means waiting for it to finish measuring
	// hundreds of servers before anything is selected at all, and until then the
	// group answers with whichever node happens to be first — frequently a dead
	// one.
	if len(s.candidates) == 0 {
		// A provider's own document comes with its own selection; take it as-is.
		code, err := waitForHealthy(ctx, probe)
		if err != nil {
			return fmt.Errorf("session: the engine started but carried no traffic: %w", err)
		}
		s.healthCode = code
		return nil
	}

	attempts := opts.MaxAttempts
	if attempts > len(s.candidates) {
		attempts = len(s.candidates)
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		candidate := s.candidates[i]
		selectCtx, selectCancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.process.ChangeProxy(selectCtx, mihomoconf.SelectGroup, candidate)
		selectCancel()
		if err != nil {
			lastErr = fmt.Errorf("select %q: %w", candidate, err)
			continue
		}

		code, err := waitForHealthy(ctx, probe)
		if err == nil {
			s.healthCode = code
			s.selected = candidate
			return nil
		}
		lastErr = fmt.Errorf("%q: %w", candidate, err)
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("session: no node carried traffic after %d attempts: %w", attempts, lastErr)
}

// Select moves a running session onto another node.
//
// It holds the new node to the same standard connecting is held to — a real
// request has to complete through it — and puts the previous node back when it
// does not, because a dashboard row that changed is not worth a connection that
// stopped working.
func (s *Session) Select(ctx context.Context, node string) error {
	if s.process == nil {
		return fmt.Errorf("session: nothing is running")
	}
	if len(s.candidates) == 0 {
		return fmt.Errorf("session: this subscription selects its own node")
	}

	previous := s.selected
	if err := s.changeProxy(ctx, node); err != nil {
		return err
	}

	code, err := waitForHealthy(ctx, func(probeCtx context.Context) int { return probeStatus(probeCtx, s.mixedPort) })
	if err != nil {
		if previous != "" && previous != node {
			if restoreErr := s.changeProxy(ctx, previous); restoreErr == nil {
				return fmt.Errorf("session: %q carried no traffic, so %q is still in use: %w", node, previous, err)
			}
		}
		return fmt.Errorf("session: %q carried no traffic: %w", node, err)
	}

	s.healthCode = code
	s.selected = node
	return nil
}

func (s *Session) changeProxy(ctx context.Context, node string) error {
	selectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.process.ChangeProxy(selectCtx, mihomoconf.SelectGroup, node); err != nil {
		return fmt.Errorf("session: select %q: %w", node, err)
	}
	return nil
}

// Close stops the engine.
func (s *Session) Close() error {
	if s.process == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.process.Stop(ctx)
}

// PrepareConfig renders the configuration for these options without starting
// anything, and returns the node names available for selection.
//
// The names come back empty for a provider's own mihomo document: it arrives
// with its own groups and selection, and overriding that would discard choices
// the provider made deliberately.
func PrepareConfig(opts Options) (string, []string, error) {
	opts = withDefaults(opts)

	body := strings.TrimSpace(opts.Subscription)
	if body == "" {
		return "", nil, fmt.Errorf("session: the subscription is empty")
	}

	var (
		proxiesYAML string
		candidates  []string
		group       string
	)
	if proxies, err := mihomoconf.ConvertLinks(body); err == nil {
		if opts.FrontingIP != "" {
			// Nodes fronting cannot be applied to are left reachable at their own
			// address rather than dropped: a front that covers most of the list is
			// better than a list cut down to what it covers.
			proxies, _ = mihomoconf.FrontProxies(proxies, opts.FrontingIP)
		}
		// Share links, which is what the WhiteDNS catalogue is. They carry nodes
		// only, so the groups and rule have to be generated around them.
		document, buildErr := mihomoconf.BuildProxiesYAML(proxies)
		if buildErr != nil {
			return "", nil, buildErr
		}
		proxiesYAML = document
		candidates = make([]string, 0, len(proxies))
		for _, proxy := range proxies {
			candidates = append(candidates, proxy.Name())
		}
		if len(opts.Prefer) > 0 {
			preferred := intersect(candidates, opts.Prefer)
			if len(preferred) == 0 {
				return "", nil, fmt.Errorf("session: none of the chosen nodes are in the subscription")
			}
			candidates = preferred
		}
		group = mihomoconf.SelectGroup
	} else if looksLikeMihomoYAML(body) {
		// Already a mihomo document: pass it through and let its own groups and
		// rules stand, including whichever node they select.
		proxiesYAML = body
		group = detectProxyGroup(body)
	} else {
		return "", nil, fmt.Errorf("session: subscription is neither usable share links nor mihomo YAML: %w", err)
	}

	secret, err := randomSecret()
	if err != nil {
		return "", nil, err
	}

	document := mihomoconf.Render(proxiesYAML, mihomoconf.Options{
		MixedPort:   opts.MixedPort,
		ControlPort: opts.ControlPort,
		Secret:      secret,
		DNSPrivacy:  opts.DNSPrivacy,
		DoHURL:      opts.DoHURL,
		DoTEndpoint: opts.DoTEndpoint,
		ProxyGroup:  group,
		Tun:         opts.Tun,
	})
	return document, candidates, nil
}

// intersect keeps the wanted names that the subscription actually yielded, in
// the order they were wanted.
func intersect(available []string, wanted []string) []string {
	present := make(map[string]bool, len(available))
	for _, name := range available {
		present[name] = true
	}
	kept := make([]string, 0, len(wanted))
	seen := make(map[string]bool, len(wanted))
	for _, name := range wanted {
		if !present[name] || seen[name] {
			continue
		}
		seen[name] = true
		kept = append(kept, name)
	}
	return kept
}

func looksLikeMihomoYAML(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "proxies:") || strings.HasPrefix(line, "proxy-groups:") {
			return true
		}
	}
	return false
}

// countProxies counts entries under `proxies:` only. Groups use the same
// `- name:` shape, so counting them across the whole document reports every
// group as a server.
func countProxies(body string) int {
	count := 0
	inProxies := false
	for _, line := range strings.Split(body, "\n") {
		if isTopLevelKey(line) {
			inProxies = strings.HasPrefix(line, "proxies:")
			continue
		}
		if inProxies && strings.HasPrefix(strings.TrimSpace(line), "- name:") {
			count++
		}
	}
	return count
}

func isTopLevelKey(line string) bool {
	if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "-") {
		return false
	}
	return strings.Contains(line, ":")
}

// detectProxyGroup finds the group DNS should resolve through. Preferring the
// app's own group name keeps a subscription that already carries it behaving the
// way the phone expects; otherwise the first group declared is the best guess.
func detectProxyGroup(body string) string {
	var first string
	inGroups := false
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "proxy-groups:") {
			inGroups = true
			continue
		}
		if inGroups && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			break
		}
		if !inGroups {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- name:") {
			continue
		}
		name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:")), `"'`)
		if name == mihomoconf.SelectGroup {
			return name
		}
		if first == "" {
			first = name
		}
	}
	return first
}

func withDefaults(opts Options) Options {
	if opts.MixedPort == 0 {
		opts.MixedPort = mihomoconf.DefaultMixedPort
	}
	if opts.ControlPort == 0 {
		opts.ControlPort = mihomoconf.DefaultControlPort
	}
	if opts.DNSPrivacy == "" {
		opts.DNSPrivacy = mihomoconf.DNSAutomatic
	}
	if opts.MaxAttempts <= 0 {
		// Five, as the phone app allows itself for startup attempts.
		opts.MaxAttempts = 5
	}
	return opts
}

func randomSecret() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("session: generate control secret: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

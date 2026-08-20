package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

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

	// AllowLAN opens the local proxy to the rest of the network, which is how a
	// phone on the same hotspot reaches this desktop's connection.
	AllowLAN bool

	// Chain sends traffic through a second node before the internet. Empty means
	// one hop, which is the ordinary case.
	//
	// Only the link-based path honours it. A subscription that arrives as a whole
	// mihomo document brings its own groups and rules, and rewriting somebody
	// else's routing to insert a hop is a different and much larger promise than
	// the one this makes.
	Chain mihomoconf.Chain

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

	// Exclude drops nodes from the configuration entirely, by name. It is how a
	// node the user hid stays hidden.
	//
	// Dropped rather than merely not preferred, and that distinction matters:
	// Prefer narrows what an attempt reaches for while leaving everything in the
	// group, so a hidden node expressed as a preference would still be sitting in
	// the url-test group for the engine to choose. It would also make Prefer
	// non-empty and turn Automatic into an explicit selection, losing the group
	// that makes Automatic work at all.
	Exclude []string

	// VerifyTLSIntegrity refuses a node whose certificates do not verify through
	// the tunnel, which is what interception looks like from here.
	VerifyTLSIntegrity bool

	// SplitTunnel routes named programs around the tunnel, or only them through
	// it. Empty means everything goes through it.
	SplitTunnel mihomoconf.SplitTunnel

	// Noise pads WireGuard proxies so their shape is less recognisable. It
	// reaches nothing else, because the noise is AmneziaWG's and mihomo has
	// nowhere to put it on a vless or trojan proxy.
	Noise mihomoconf.AmneziaNoise

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

	// automatic means the engine's url-test group is choosing, rather than this
	// app having pinned one node. It is false when the user named what to use,
	// and false for a provider document that selects for itself.
	automatic bool

	// seeded is how many of the sampled nodes answered before the group was
	// selected. It is worth logging: a connect where nothing answered says
	// something about the network, not about the catalogue.
	seeded int

	// tunnelUnverified is set when the tunnel was accepted without being checked,
	// which happens on platforms that have no way to read an adapter's routes yet.
	tunnelUnverified error

	// reasons carries whatever the engine last said about why a dial failed.
	reasons *coreReasonTap
}

// Seeded is how many sampled nodes answered a delay test before the automatic
// group was asked to choose.
func (s *Session) Seeded() int { return s.seeded }

// TunnelUnverified is non-nil when the tunnel is up but could not be inspected,
// so the caller can say so instead of implying it was checked.
func (s *Session) TunnelUnverified() error { return s.tunnelUnverified }

// Selected is the node currently carrying traffic.
//
// Under automatic selection this is whichever node the engine's group had chosen
// when it was last asked, not a node this app pinned.
func (s *Session) Selected() string { return s.selected }

// Automatic reports whether the engine is choosing the node.
func (s *Session) Automatic() bool { return s.automatic }

// RefreshSelection re-reads which node the engine's group is on, and reports
// whether that has changed since the last look.
//
// Under automatic selection the group moves on its own, so a name shown once at
// connect time goes stale — the dashboard would keep naming a node the traffic
// stopped using. Nothing is reported when the lookup fails or the group has not
// settled, because replacing a name that was right with no name at all is worse
// than a name that is a few seconds old.
func (s *Session) RefreshSelection(ctx context.Context) (string, bool) {
	if s.process == nil || !s.automatic {
		return s.selected, false
	}
	name := s.resolveSelection(ctx)
	if name == "" || name == s.selected {
		return s.selected, false
	}
	s.selected = name
	return name, true
}

// resolveSelection asks the engine which node its group settled on, so the
// interface can name a place rather than a group.
func (s *Session) resolveSelection(ctx context.Context) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	proxies, err := proxySnapshot(lookupCtx, s.process)
	if err != nil {
		return ""
	}
	name := resolveGroup(proxies, mihomoconf.SelectGroup)
	if name == mihomoconf.SelectGroup || name == mihomoconf.AutoGroup {
		// The group answered with itself, which means it has not settled yet.
		// Naming nothing beats naming a group.
		return ""
	}
	return name
}

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

	// Read on the way past, so a failure can say what the engine said rather
	// than only that nothing worked. Both streams: the engine's log, dial
	// failures included, goes to stdout. See corereason.go.
	reasons := newCoreReasonTap()

	process, err := engine.Spawn(ctx, engine.SpawnOptions{
		CorePath:       opts.CorePath,
		WorkingDir:     opts.HomeDir,
		ConnectTimeout: 20 * time.Second,
		Stdout:         reasons.Watch(opts.CoreStdout),
		Stderr:         reasons.Watch(opts.CoreStderr),
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
		// The generated configuration is the only one that carries a url-test
		// group, and a stated preference is the user choosing for themselves.
		automatic: len(candidates) > 0 && len(opts.Prefer) == 0,
		reasons:   reasons,
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
	acceptHealthy := func(code int) error {
		// Carrying traffic is not the same as carrying it privately. If whatever
		// sits between here and the internet is terminating TLS, every request
		// succeeds and the connection is being read — so a node that answers is
		// still refused when its certificates do not verify.
		if opts.VerifyTLSIntegrity {
			if err := verifyTLSIntegrity(ctx, opts.MixedPort); err != nil {
				return err
			}
		}
		if opts.Tun.Enabled {
			switch err := waitForTunnel(ctx, opts.Tun.Device, opts.Tun.IPv6); {
			case err == nil:
			case errors.Is(err, errTunnelUnverifiable):
				s.tunnelUnverified = err
			default:
				return fmt.Errorf("session: tunnel verification failed: %w", err)
			}
		}
		s.healthCode = code
		return nil
	}

	if len(s.candidates) == 0 {
		// A provider's own document comes with its own selection; take it as-is.
		code, err := waitForHealthy(ctx, probe)
		if err != nil {
			return fmt.Errorf("session: the engine started but carried no traffic: %w%s", err, s.engineSaid())
		}
		return acceptHealthy(code)
	}

	var lastErr error

	// Automatic hands the choice to the engine, which is what the phone app does
	// and why it behaves the way it does.
	//
	// This used to pick a node itself and pin the group to it. With a catalogue of
	// eight hundred nodes that was the wrong shape twice over: every user tried the
	// same five, in the same order, so a bad head of the list told everybody the app
	// could not connect; and once pinned, a `select` group never reconsiders, so a
	// node that died mid-session stayed selected until a watchdog noticed.
	//
	// A url-test group measures its members continuously, picks the fastest that
	// answers, and — this is the part that matters — moves off a node by itself once
	// dialling through it starts failing. Eight hundred nodes stop being eight
	// hundred chances to fail and become eight hundred chances to succeed.
	if s.automatic {
		// Measure a random sample first, so the group has real numbers to choose
		// between rather than eight hundred nodes that all look the same to it.
		// See seed.go for why this is not optional.
		s.seeded = s.seedMeasurements(ctx, s.candidates)

		if err := s.changeProxy(ctx, mihomoconf.AutoGroup); err != nil {
			lastErr = err
		} else {
			code, err := waitForHealthy(ctx, probe)
			if err == nil {
				if err := acceptHealthy(code); err != nil {
					// Interception is about this node, not about the app: reject
					// it and let the walk below try another. Anything else — a
					// tunnel that never came up — is not survivable by changing
					// node.
					if !errors.Is(err, ErrTLSIntercepted) {
						return err
					}
					lastErr = err
				} else {
					s.selected = s.resolveSelection(ctx)
					return nil
				}
			} else {
				lastErr = fmt.Errorf("automatic selection: %w", err)
			}
		}
	}

	// Nothing answered through the group, or the user named the nodes to use.
	// Either way this walks them one at a time, fastest first.
	//
	// A user who picks a country gets the same treatment for the same reason: that
	// country may hold eighty nodes, and walking the first five of them in
	// catalogue order is the same mistake in a smaller list.
	if !s.automatic {
		s.seeded = s.seedMeasurements(ctx, s.candidates)
	}
	order := s.candidates
	if proxies, err := proxySnapshot(ctx, s.process); err == nil {
		order = byMeasuredDelay(order, proxies)
	}

	attempts := opts.MaxAttempts
	if attempts > len(order) {
		attempts = len(order)
	}

	for i := 0; i < attempts; i++ {
		candidate := order[i]
		selectCtx, selectCancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.process.ChangeProxy(selectCtx, mihomoconf.SelectGroup, candidate)
		selectCancel()
		if err != nil {
			lastErr = fmt.Errorf("select %q: %w", candidate, err)
			continue
		}

		code, err := waitForHealthy(ctx, probe)
		if err == nil {
			if err := acceptHealthy(code); err != nil {
				if !errors.Is(err, ErrTLSIntercepted) {
					return err
				}
				// This node's certificates did not verify. Another may.
				lastErr = fmt.Errorf("%q: %w", candidate, err)
				continue
			}
			// The group is pinned to this node now, so the engine is no longer the
			// one choosing and recovery has to do the choosing instead.
			s.automatic = false
			s.selected = candidate
			return nil
		}
		lastErr = fmt.Errorf("%q: %w", candidate, err)
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("session: no node carried traffic after %d attempts: %w%s",
		attempts, lastErr, s.engineSaid())
}

// engineSaid is the engine's own explanation, ready to append to a failure.
//
// It is what turns "no request completed through the proxy within 12s" — true,
// and no help at all — into something a user can act on. "REALITY
// authentication failed" says the keys no longer match the server; "connection
// refused" says the server is not listening. The engine knew all along and the
// app was dropping it on the floor.
func (s *Session) engineSaid() string {
	reason := s.reasons.Reason()
	if reason == "" {
		return ""
	}
	return fmt.Sprintf(" (the engine reported: %s)", reason)
}

// Healthy reports whether a real request still completes through this session.
func (s *Session) Healthy(ctx context.Context) bool {
	return healthy(probeStatus(ctx, s.mixedPort))
}

// Recover moves a stranded session onto a node that works.
//
// Connecting proves one node carries traffic and then pins the group to it for
// the rest of the session. A node that stops carrying traffic afterwards — the
// front it sits behind starts answering 502, the server is restarted, the
// address is blocked — leaves the app connected, the proxy listening, the
// dashboard green, and every request failing. The catalogue holds hundreds of
// alternatives and nothing was reaching for them.
//
// The node that just failed is skipped, and the previous selection is left in
// place if nothing better is found: a session on a bad node is worth more than
// a session on no node, because the bad one may come back.
func (s *Session) Recover(ctx context.Context, attempts int) (string, error) {
	if s.process == nil {
		return "", fmt.Errorf("session: nothing is running")
	}
	if len(s.candidates) == 0 {
		return "", fmt.Errorf("session: this subscription selects its own node")
	}

	// Under automatic selection the engine is already recovering: a url-test group
	// re-measures after a run of failed dials and moves off a dead node without
	// being asked. Pinning a node here would take that away — it would replace a
	// group that keeps looking with one node that never gets reconsidered. So this
	// waits for the engine's own move and reports where it went.
	if s.automatic {
		return s.recoverAutomatically(ctx)
	}

	// The measurements are stale by now — they were taken when this session was
	// made, and what has changed since is precisely why recovery is running. A
	// fresh sample means the alternatives are ordered by how they are behaving
	// now rather than by how they behaved when the connection still worked.
	s.seeded = s.seedMeasurements(ctx, s.candidates)
	ordered := s.candidates
	if proxies, err := proxySnapshot(ctx, s.process); err == nil {
		ordered = byMeasuredDelay(ordered, proxies)
	}

	previous := s.selected
	var lastErr error
	for _, candidate := range recoveryOrder(ordered, previous, attempts) {
		if ctx.Err() != nil {
			break
		}
		selectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.process.ChangeProxy(selectCtx, mihomoconf.SelectGroup, candidate)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("select %q: %w", candidate, err)
			continue
		}
		code, err := waitForHealthy(ctx, func(probeCtx context.Context) int {
			return probeStatus(probeCtx, s.mixedPort)
		})
		if err == nil {
			s.healthCode = code
			s.selected = candidate
			return candidate, nil
		}
		lastErr = fmt.Errorf("%q: %w", candidate, err)
	}

	if previous != "" {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = s.process.ChangeProxy(restoreCtx, mihomoconf.SelectGroup, previous)
		cancel()
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no other node to try")
	}
	return "", fmt.Errorf("session: nothing else carried traffic either: %w", lastErr)
}

// recoverAutomatically waits for the engine's group to move itself off a node
// that stopped working, and reports where it landed.
//
// Re-asserting the selection is what prompts it: the group answers with its own
// current pick, and mihomo re-checks a group whose dials keep failing. If the
// group has not moved by the time the budget is spent, the failure says so
// rather than pretending — but the session is left alone either way, because a
// group that is still looking is worth more than a node pinned by hand.
func (s *Session) recoverAutomatically(ctx context.Context) (string, error) {
	previous := s.selected

	// A fresh random sample, because the group can only choose between nodes it
	// has numbers for, and if the ones it had have gone the way of the node that
	// just failed, it needs new ones to look at.
	s.seeded = s.seedMeasurements(ctx, s.candidates)

	if err := s.changeProxy(ctx, mihomoconf.AutoGroup); err != nil {
		return "", err
	}
	code, err := waitForHealthy(ctx, func(probeCtx context.Context) int {
		return probeStatus(probeCtx, s.mixedPort)
	})
	if err != nil {
		return "", fmt.Errorf("session: the automatic group has not found a node that answers: %w", err)
	}

	s.healthCode = code
	s.selected = s.resolveSelection(ctx)
	if s.selected == "" {
		s.selected = previous
	}
	return s.selected, nil
}

// withoutNodes removes the named nodes from a subscription's proxies.
//
// Hiding everything is refused rather than allowed to produce an empty
// configuration: the engine would fail to start and the error would be about a
// missing group, which says nothing about what the user actually did.
func withoutNodes(proxies []mihomoconf.Proxy, exclude []string) ([]mihomoconf.Proxy, error) {
	drop := make(map[string]struct{}, len(exclude))
	for _, name := range exclude {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			drop[trimmed] = struct{}{}
		}
	}
	if len(drop) == 0 {
		return proxies, nil
	}

	kept := make([]mihomoconf.Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		if _, hidden := drop[proxy.Name()]; hidden {
			continue
		}
		kept = append(kept, proxy)
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("session: every node in this subscription is hidden")
	}
	return kept, nil
}

// recoveryOrder is which nodes a recovery reaches for: the candidates in their
// own order, without the one that just failed, capped at what one recovery is
// willing to spend.
func recoveryOrder(candidates []string, skip string, limit int) []string {
	out := make([]string, 0, limit)
	for _, candidate := range candidates {
		if candidate == skip || len(out) >= limit {
			continue
		}
		out = append(out, candidate)
	}
	return out
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
	// What the group has to be put back to, which under automatic selection is
	// the group itself rather than the node it happens to be on. Restoring the
	// node would quietly pin a session that was choosing for itself.
	restore := previous
	if s.automatic {
		restore = mihomoconf.AutoGroup
	}

	if err := s.changeProxy(ctx, node); err != nil {
		return err
	}

	code, err := waitForHealthy(ctx, func(probeCtx context.Context) int { return probeStatus(probeCtx, s.mixedPort) })
	if err != nil {
		if restore != "" && restore != node {
			if restoreErr := s.changeProxy(ctx, restore); restoreErr == nil {
				return fmt.Errorf("session: %q carried no traffic, so %q is still in use: %w", node, previous, err)
			}
		}
		return fmt.Errorf("session: %q carried no traffic: %w%s", node, err, s.engineSaid())
	}

	s.healthCode = code
	// A node named by hand is the user choosing, so the engine stops choosing.
	s.automatic = false
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
	// One parser for every shape a subscription arrives in, so a mihomo document
	// yields the same []Proxy as a list of share links and everything after this
	// point — groups, rules, node selection, fronting — is identical for both.
	// The document's own groups and rules are deliberately not carried over: a
	// user picking a node on the Servers page expects that node, not whatever
	// the provider's url-test group decides.
	if proxies, _, err := mihomoconf.ParseSubscription(body); err == nil {
		if len(opts.Exclude) > 0 {
			kept, err := withoutNodes(proxies, opts.Exclude)
			if err != nil {
				return "", nil, err
			}
			proxies = kept
		}
		// Before fronting, which only rewrites addresses: the two are
		// independent and a WireGuard node can have both.
		proxies, _ = mihomoconf.ApplyAmneziaNoise(proxies, opts.Noise)
		if opts.FrontingIP != "" {
			// Nodes fronting cannot be applied to are left reachable at their own
			// address rather than dropped: a front that covers most of the list is
			// better than a list cut down to what it covers.
			proxies, _ = mihomoconf.FrontProxies(proxies, opts.FrontingIP)
		}
		// Share links, which is what the WhiteDNS catalogue is. They carry nodes
		// only, so the groups and rule have to be generated around them.
		document, firstHop, buildErr := mihomoconf.BuildProxiesYAMLWithChain(proxies, opts.SplitTunnel, opts.Chain)
		if buildErr != nil {
			return "", nil, buildErr
		}
		proxiesYAML = document
		// What the first hop may be, which is not every node once a chain is in
		// play: the exit's own is taken out so both ends cannot be one machine,
		// and a datagram exit narrows it to nodes that can carry UDP. Selecting
		// outside this would name a proxy the group does not contain.
		candidates = append([]string(nil), firstHop...)
		if len(opts.Prefer) > 0 {
			preferred := intersect(candidates, opts.Prefer)
			if len(preferred) == 0 {
				return "", nil, fmt.Errorf("session: none of the chosen nodes are in the subscription")
			}
			candidates = preferred
		}
		group = mihomoconf.SelectGroup
	} else if looksLikeMihomoDocument(body) {
		// A mihomo document whose proxies could not be read as a list — the
		// usual reason is `proxy-providers`, where the nodes are fetched by the
		// engine rather than written inline. There is nothing to extract, so it
		// is passed through and its own groups and rules stand, including
		// whichever node they select.
		proxiesYAML = body
		group = detectProxyGroup(body)
	} else {
		return "", nil, fmt.Errorf("session: subscription is neither usable share links nor a mihomo configuration: %w", err)
	}

	secret, err := randomSecret()
	if err != nil {
		return "", nil, err
	}

	document := mihomoconf.Render(proxiesYAML, mihomoconf.Options{
		MixedPort:   opts.MixedPort,
		ControlPort: opts.ControlPort,
		AllowLAN:    opts.AllowLAN,
		Secret:      secret,
		DNSPrivacy:  opts.DNSPrivacy,
		DoHURL:      opts.DoHURL,
		DoTEndpoint: opts.DoTEndpoint,
		ProxyGroup:  group,
		Tun:         opts.Tun,
		SplitTunnel: opts.SplitTunnel,
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

// looksLikeMihomoDocument decides by parsing rather than by looking at the
// start of a line.
//
// The line-prefix version missed every configuration served as JSON — where the
// key reads `    "proxies": [` — and JSON is what the panel that prompted this
// serves. It also missed any YAML that indented its top level or opened with a
// `---`. Reading the document costs microseconds and cannot be wrong about it.
func looksLikeMihomoDocument(body string) bool {
	var document struct {
		Proxies        []any          `yaml:"proxies"`
		ProxyGroups    []any          `yaml:"proxy-groups"`
		ProxyProviders map[string]any `yaml:"proxy-providers"`
	}
	if err := yaml.Unmarshal([]byte(body), &document); err != nil {
		return false
	}
	return len(document.Proxies) > 0 || len(document.ProxyGroups) > 0 || len(document.ProxyProviders) > 0
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
		// Five, as the phone app allows itself for startup attempts. This caps the
		// fallback walk, which now runs in measured order, so it is five nodes the
		// engine has numbers for rather than five arbitrary ones off the top of the
		// catalogue.
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

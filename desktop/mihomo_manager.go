package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/mihomoconf"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
	"whitevpn-desktop/internal/sessionmanager"
)

func (a *App) connectionManager() *sessionmanager.Manager {
	a.connectionOnce.Do(func() {
		a.connection = sessionmanager.New(20 * time.Second)
		backend := a.connectionBackend
		if backend == nil {
			backend = &mihomoBackend{app: a}
		}
		if err := a.connection.Register(sessionmanager.Mihomo, backend); err != nil {
			panic(err)
		}
		if a.connectionBackend == nil {
			for _, kind := range engineprofiles.Kinds() {
				if kind.SOCKS() {
					if err := a.connection.Register(kind, &engineBackend{app: a}); err != nil {
						panic(err)
					}
				}
			}
		}
	})
	return a.connection
}

func (a *App) hasManagedOwner() bool { return a.connectionManager().HasOwner() }

type mihomoBackend struct{ app *App }

func (b *mihomoBackend) Preflight(ctx context.Context, p sessionmanager.Plan) error {
	_, _, err := session.PrepareConfig(*p.Mihomo)
	return err
}

func (b *mihomoBackend) Prepare(ctx context.Context, p sessionmanager.Plan) (sessionmanager.Plan, error) {
	prepared, err := b.prepare(ctx, p)
	reason := ""
	if err != nil {
		reason = model.PublicText(err.Error())
	}
	b.app.mu.Lock()
	b.app.preflightReason = reason
	b.app.mu.Unlock()
	return prepared, err
}

func (b *mihomoBackend) prepare(ctx context.Context, p sessionmanager.Plan) (sessionmanager.Plan, error) {
	a := b.app
	if err := a.sourceCredentialError(p.Route.SourceID); err != nil {
		return p, err
	}
	a.mu.Lock()
	settings := settingsForThisMachine(model.NormalizeWhiteVPNSettings(model.CloneWhiteVPNSettings(a.state.WhiteVPN)))
	a.mu.Unlock()
	if settings.DNSPrivacy.CredentialRequired && settings.DNSPrivacy.Mode != model.DNSPrivacyAutomatic {
		return p, model.ErrCredentialsRequired
	}
	// A replacement is prepared while the healthy old session remains active.
	if a.connectionManager().Snapshot().Phase != sessionmanager.Connected {
		a.setMihomoRuntimeType()
		a.handleRuntimeState(model.RuntimeConnecting, "Fetching subscription")
	}
	core, err := findMihomoCore()
	if err != nil {
		return p, err
	}
	var (
		body, usedID string
		nodes        []model.WhiteVPNNode
		prefer       []string
		exclude      []string
		chain        mihomoconf.Chain
	)
	if settings.Chain.Active() {
		// The chain names its own two nodes, from whichever lists they are in,
		// so the VPN page's subscription, location and connection do not apply.
		usedID = p.Route.SourceID
		body, chain, err = a.chainSubscription(ctx, settings.Chain)
		if err != nil {
			return p, err
		}
	} else {
		body, usedID, err = a.subscriptionBodyWithFallback(ctx)
		if err != nil {
			return p, err
		}
		nodes, err = whiteVPNNodesFromSubscription(body)
		if err != nil {
			return p, err
		}
		prefer = preferredNodeNames(nodes, settings)
		if len(prefer) == 0 && selectionIsNarrowed(settings) {
			return p, fmt.Errorf("no node matches the chosen location or connection")
		}
		exclude = a.hiddenNodeNames(usedID)
	}
	port, err := chooseProxyPort(settings)
	// A fixed proxy port owned by the old session will be released before Start.
	if err != nil {
		old := a.mihomo.current()
		if old == nil || old.MixedPort() != settings.ListenPort {
			return p, err
		}
		port = old.MixedPort()
	}
	fronting := ""
	if len(settings.FrontingIPs) > 0 {
		fronting = settings.FrontingIPs[0]
	}
	opts := session.Options{CorePath: core, HomeDir: filepath.Join(a.configDir, "mihomo"), MixedPort: port,
		Subscription: body, Prefer: prefer, Exclude: exclude, AllowLAN: settings.AllowLAN,
		Chain: chain, SplitTunnel: splitTunnelFor(settings), Direct: directRouteFor(settings),
		VerifyTLSIntegrity: settings.TLSIntegrityEnabled, Noise: amneziaNoiseFor(settings), FrontingIP: fronting,
		Fragments: settings.Fragments, AutoECH: settings.AutoECH,
		DNSPrivacy: dnsPrivacyMode(settings.DNSPrivacy.Mode), DoHURL: settings.DNSPrivacy.DoHURL, DoTEndpoint: settings.DNSPrivacy.DoTEndpoint, Tun: tunOptionsFor(settings)}
	p.Mode = "proxy"
	if settings.TunEnabled {
		p.Mode = "tun"
	} else if !settings.SetSystemProxy {
		p.Mode = "proxy-only"
	}
	p.Mihomo = &opts
	p.Route.SourceID = usedID
	if err := b.Preflight(ctx, p); err != nil {
		return p, err
	}
	// A chain's document is not stored: it is two lists' configs under new
	// names, and filed under one subscription it would replace that list's.
	if !chain.Active() {
		a.storeWhiteVPNNodes(usedID, nodes, time.Now().UTC())
	}
	return p, nil
}

func (b *mihomoBackend) Start(startup, lifetime context.Context, p sessionmanager.ActivePlan) (sessionmanager.Session, error) {
	return b.app.startManagedMihomo(startup, lifetime, p)
}

// startManagedMihomo is shared by subscription and engine routes: an engine
// route is the same Mihomo session whose only proxy is the engine's SOCKS port.
func (a *App) startManagedMihomo(startup, lifetime context.Context, p sessionmanager.ActivePlan) (*managedMihomoSession, error) {
	a.syncManagedRuntime()
	opts := p.Mihomo.Clone()
	opts.HomeDir = filepath.Join(opts.HomeDir, p.SessionID)
	p.Mihomo = &opts
	opts.CoreStdout = managedMihomoLogWriter{app: a, id: p.SessionID, generation: p.Generation}
	opts.CoreStderr = opts.CoreStdout
	core, err := session.ConnectOwned(startup, opts)
	if core == nil {
		core = &session.Session{}
		if err == nil {
			err = fmt.Errorf("Mihomo did not return an owned session")
		}
	}
	workerCtx, cancel := context.WithCancel(lifetime)
	owned := &managedMihomoSession{app: a, core: core, plan: p, workersCtx: workerCtx, cancelWorkers: cancel, acceptWorkers: true}
	a.managedMu.Lock()
	a.managedMihomo = owned
	a.managedMu.Unlock()
	a.mihomo.swap(core)
	if err == nil && core.FragmentMode() != "" && core.FragmentMode() != "full" {
		a.appendRuntimeLog("Fragments: connected using " + core.FragmentMode() + " fallback")
	}
	return owned, err
}

type managedMihomoSession struct {
	app           *App
	core          *session.Session
	plan          sessionmanager.ActivePlan
	workersMu     sync.Mutex
	workers       sync.WaitGroup
	workersCtx    context.Context
	cancelWorkers context.CancelFunc
	acceptWorkers bool
}

func (s *managedMihomoSession) WaitReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.plan.Mode == "proxy" {
		if err := s.app.captureSystemProxy(s.core.MixedPort()); err != nil {
			// Preserve proxy-only usability if this desktop cannot set a proxy.
			s.app.appendRuntimeLog("Connected, but this desktop's proxy settings could not be changed; configure your program's proxy manually")
			s.app.emit("runtime:notice", "Connected, but this desktop's proxy settings could not be changed; configure your program's proxy manually")
		}
	}
	return ctx.Err()
}

func (s *managedMihomoSession) launch(fn func(context.Context)) {
	s.workersMu.Lock()
	defer s.workersMu.Unlock()
	if !s.acceptWorkers {
		return
	}
	s.workers.Add(1)
	go func() { defer s.workers.Done(); fn(s.workersCtx) }()
}

func (s *managedMihomoSession) Stop(ctx context.Context) error {
	s.workersMu.Lock()
	s.acceptWorkers = false
	s.cancelWorkers()
	s.workersMu.Unlock()
	joined := make(chan struct{})
	go func() { s.workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := s.core.Stop(ctx); err != nil {
		return err
	}
	if s.plan.Mihomo.Tun.Enabled {
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range ifaces {
			if iface.Name == s.plan.Mihomo.Tun.Device {
				return fmt.Errorf("the tunnel adapter is still present")
			}
		}
	}
	s.app.restoreSystemProxy()
	if _, err := os.Stat(s.app.systemProxyBackupPath()); err == nil || !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("system proxy cleanup is not confirmed")
	}
	if filepath.Base(s.plan.Mihomo.HomeDir) != s.plan.SessionID {
		return fmt.Errorf("invalid session directory")
	}
	if err := os.RemoveAll(s.plan.Mihomo.HomeDir); err != nil {
		return fmt.Errorf("session files could not be removed")
	}
	// Remove the pointer only after all owned resources have been released.
	s.app.mihomo.swap(nil)
	s.app.managedMu.Lock()
	if s.app.managedMihomo == s {
		s.app.managedMihomo = nil
	}
	s.app.managedMu.Unlock()
	return nil
}

func (a *App) currentManagedMihomo() *managedMihomoSession {
	a.managedMu.Lock()
	defer a.managedMu.Unlock()
	return a.managedMihomo
}

func (a *App) syncManagedRuntime() {
	a.connectionEvents.Lock()
	defer a.connectionEvents.Unlock()
	a.syncManagedRuntimeLocked()
}

func (a *App) syncManagedRuntimeLocked() {
	snapshot := a.connectionManager().Snapshot()
	a.mu.Lock()
	if snapshot.Generation != a.state.Runtime.SessionGeneration && snapshot.Phase == sessionmanager.Connecting {
		a.state.Runtime.Stats = model.TrafficStats{}
		a.state.Runtime.NodeName = ""
		a.state.Runtime.NodeECH = false
		a.state.Runtime.ExitIP = ""
		a.state.Runtime.ExitCountryCode = ""
		a.state.Runtime.ExitChecked = false
	}
	a.state.Runtime.SessionID = snapshot.SessionID
	a.state.Runtime.SessionGeneration = snapshot.Generation
	a.state.Runtime.ConnectionPhase = snapshot.Phase
	a.state.Runtime.ReleasePending = snapshot.ReleasePending
	a.state.Runtime.ActiveSourceID = ""
	a.state.Runtime.FragmentMode = ""
	if snapshot.Phase == sessionmanager.Connected {
		if current := a.mihomo.current(); current != nil {
			a.state.Runtime.FragmentMode = current.FragmentMode()
		}
	}
	a.state.Runtime.EngineProfileID = ""
	if snapshot.Route != nil {
		a.state.Runtime.ActiveSourceID = snapshot.Route.SourceID
		a.state.Runtime.EngineProfileID = snapshot.Route.ProfileID
	}
	a.mu.Unlock()
	switch snapshot.Phase {
	case sessionmanager.Connected:
		a.setMihomoRuntimeType()
		a.handleRuntimeState(model.RuntimeConnected, "Connected")
	case sessionmanager.Connecting:
		a.setMihomoRuntimeType()
		a.handleRuntimeState(model.RuntimeConnecting, "Starting engine")
	case sessionmanager.Stopping:
		a.handleRuntimeState(model.RuntimeStopping, "Disconnecting")
	case sessionmanager.ReleasePending, sessionmanager.Failed:
		message := "Connection failed; review the connection settings and try again"
		if snapshot.ErrorCode == "preflight-failed" {
			if reason := a.lastPreflightReason(); reason != "" {
				message = reason
			}
		}
		if snapshot.ReleasePending {
			message = "Connection resources could not be confirmed released; disconnect again before reconnecting"
		}
		a.handleRuntimeState(model.RuntimeFailed, message)
	case sessionmanager.Disconnected:
		a.mu.Lock()
		a.state.Runtime.Engine = ""
		a.mu.Unlock()
		a.handleRuntimeState(model.RuntimeDisconnected, "Disconnected")
	}
}

type managedMihomoLogWriter struct {
	app        *App
	id         string
	generation uint64
}

func (w managedMihomoLogWriter) Write(raw []byte) (int, error) {
	w.app.connectionEvents.Lock()
	defer w.app.connectionEvents.Unlock()
	if w.app.connectionManager().Matches(w.id, w.generation) {
		_, _ = (mihomoLogWriter{app: w.app}).Write(raw)
	}
	return len(raw), nil
}

func (a *App) withMihomo(current *session.Session, fn func()) bool {
	a.connectionEvents.Lock()
	defer a.connectionEvents.Unlock()
	if a.mihomo.current() != current {
		return false
	}
	if owned := a.currentManagedMihomo(); owned != nil && !a.connectionManager().Matches(owned.plan.SessionID, owned.plan.Generation) {
		return false
	}
	fn()
	return true
}

// managedRequest is the selected route: an engine profile when one is
// selected (Android RouteSelectionMigration: the engine wins), otherwise the
// subscription. A selected profile that no longer exists is an error, never a
// silent fallback to the subscription.
func (a *App) managedRequest() (sessionmanager.Plan, error) {
	if ref := a.selectedEngineRoute(); ref != nil {
		store, err := a.engineProfileStore()
		if err != nil {
			return sessionmanager.Plan{}, err
		}
		profile, err := store.ForEdit(ref.ProfileID)
		if err != nil {
			return sessionmanager.Plan{}, errSelectedEngineMissing
		}
		return sessionmanager.Plan{Route: *ref, Profile: profile, Mode: "proxy", Mihomo: &session.Options{}}, nil
	}
	return sessionmanager.Plan{Route: engineprofiles.RouteRef{Kind: "mihomo", SourceID: a.selectedSubscriptionID()}, Mode: "proxy", Mihomo: &session.Options{}}, nil
}

func (a *App) launchMihomo(current *session.Session, fn func(context.Context)) {
	if owned := a.currentManagedMihomo(); owned != nil && owned.core == current {
		owned.launch(fn)
		return
	}
}

func (a *App) publishManagedMihomo() {
	owned := a.currentManagedMihomo()
	if owned == nil {
		return
	}
	current := owned.core
	if !a.withMihomo(current, func() {
		a.mu.Lock()
		a.state.Runtime.ListenIP = "127.0.0.1"
		a.state.Runtime.ListenPort = current.MixedPort()
		a.state.Runtime.ProxyProtocol = "mixed"
		a.state.Runtime.LocalProxyIP = "127.0.0.1"
		if owned.plan.Mihomo.AllowLAN {
			a.state.Runtime.PublicProxyIP = lanAddress()
		}
		a.state.Runtime.FrontingIP = owned.plan.Mihomo.FrontingIP
		a.mu.Unlock()
		node := current.Selected()
		if owned.plan.Route.Kind == "engine" {
			// The only proxy is the engine, so name what the user selected.
			node = owned.plan.Profile.Name
		}
		a.recordConnectedNode(node)
		a.appendRuntimeLog(fmt.Sprintf("mihomo connected: %d nodes available; proxy listening on 127.0.0.1:%d", current.ProxyCount(), current.MixedPort()))
	}) {
		return
	}
	if current.Engine() != nil {
		owned.launch(func(ctx context.Context) {
			select {
			case <-ctx.Done():
				return
			case <-current.Engine().ExitDone():
			}
			a.connectionEvents.Lock()
			defer a.connectionEvents.Unlock()
			if a.connectionManager().ReportFailure(owned.plan.SessionID, owned.plan.Generation) {
				a.syncManagedRuntimeLocked()
			}
		})
	}
	a.sampleTraffic(current)
	a.watchHealth(current)
	a.resolveExitCountry()
	a.retryBlockedSubscriptions()
}

func (a *App) lastPreflightReason() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.preflightReason
}

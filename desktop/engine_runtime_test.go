package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/engines"
	"whitevpn-desktop/internal/engines/psiphon"
	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
	"whitevpn-desktop/internal/sessionmanager"
)

// fakeEngine is a SOCKS engine that only listens.
type fakeEngine struct {
	listener net.Listener
	done     chan struct{}
	once     sync.Once
	closes   int
}

func (f *fakeEngine) SOCKSPort() int        { return f.listener.Addr().(*net.TCPAddr).Port }
func (f *fakeEngine) Done() <-chan struct{} { return f.done }
func (f *fakeEngine) exit()                 { f.once.Do(func() { _ = f.listener.Close(); close(f.done) }) }
func (f *fakeEngine) Close() error          { f.closes++; f.exit(); return nil }

func TestEngineAvailabilityFollowsRegistrationAndBinaries(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("engines run on Windows only")
	}
	a := &App{configDir: t.TempDir()}
	a.initEngineProfiles()
	got := map[engineprofiles.Kind]engineprofiles.Availability{}
	for _, entry := range a.GetEngineAvailability() {
		got[entry.Kind] = entry
	}
	present := shippedBinaryPresent(psiphon.BinaryName())
	if p := got[engineprofiles.Psiphon]; p.Available != present || (!present && p.Reason != "binary-missing") || !p.Capabilities.Country {
		t.Fatalf("psiphon availability = %+v with binary present=%v", p, present)
	}
	if _, registered := engines.Lookup(engineprofiles.Tor); !registered && got[engineprofiles.Tor].Reason != "backend-not-installed" {
		t.Fatalf("tor without a starter = %+v", got[engineprofiles.Tor])
	}
	for _, kind := range []engineprofiles.Kind{engineprofiles.SSH, engineprofiles.DNS, engineprofiles.AmneziaWG, engineprofiles.IKEv2} {
		if got[kind].Available {
			t.Fatalf("%s reported available", kind)
		}
	}
	engines.Register(engineprofiles.DNS, engines.Engine{Start: func(context.Context, engines.StartOptions) (engines.Process, error) { return nil, errors.New("x") }, Binaries: []string{"not-shipped.exe"}})
	defer engines.Unregister(engineprofiles.DNS)
	if reason := a.engineUnavailable(engineprofiles.DNS); reason != "binary-missing" {
		t.Fatalf("missing binary reason = %q", reason)
	}
}

func TestFakeEngineRunsThroughSessionManager(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("user-scoped DPAPI vault requires Windows")
	}
	a := &App{configDir: t.TempDir(), state: model.DefaultAppState()}
	free, _ := engines.FreePort()
	a.state.WhiteVPN.TunEnabled = false
	a.state.WhiteVPN.SetSystemProxy = false // proxy-only: never touch this machine's settings
	a.state.WhiteVPN.ListenPort = free
	a.initEngineProfiles()

	var fake *fakeEngine
	engines.Register(engineprofiles.SSH, engines.Engine{Start: func(ctx context.Context, opts engines.StartOptions) (engines.Process, error) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		fake = &fakeEngine{listener: l, done: make(chan struct{})}
		return fake, nil
	}})
	defer engines.Unregister(engineprofiles.SSH)
	var seen session.Options
	oldCore, oldStart := engineMihomoCore, engineStartMihomo
	defer func() { engineMihomoCore, engineStartMihomo = oldCore, oldStart }()
	engineMihomoCore = func() (string, error) { return "fake-mihomo.exe", nil }
	engineStartMihomo = func(a *App, startup, lifetime context.Context, p sessionmanager.ActivePlan) (*managedMihomoSession, error) {
		opts := p.Mihomo.Clone()
		opts.HomeDir = filepath.Join(opts.HomeDir, p.SessionID)
		p.Mihomo = &opts
		seen = opts
		ctx, cancel := context.WithCancel(lifetime)
		return &managedMihomoSession{app: a, core: &session.Session{}, plan: p, workersCtx: ctx, cancelWorkers: cancel, acceptWorkers: true}, nil
	}

	summary, err := a.SaveEngineProfile(disposableSSHProfile)
	if err != nil {
		t.Fatal(err)
	}
	if req, err := a.managedRequest(); err != nil || req.Route.Kind != "mihomo" || a.GetSelectedEngineProfileID() != "" {
		t.Fatal("a fresh catalog must keep the subscription route")
	}
	if err := a.SelectEngineProfile(summary.ID); err != nil {
		t.Fatal(err)
	}
	reopened := &App{configDir: a.configDir}
	reopened.initEngineProfiles()
	if reopened.GetSelectedEngineProfileID() != summary.ID {
		t.Fatal("engine selection did not persist")
	}
	req, err := a.managedRequest()
	if err != nil || req.Route.Kind != "engine" || req.Route.ProfileID != summary.ID {
		t.Fatalf("selected engine route = %+v, %v", req.Route, err)
	}
	manager := a.connectionManager()
	if err := manager.Connect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if snapshot.Phase != sessionmanager.Connected || snapshot.Route.ProfileID != summary.ID || snapshot.Mode != "proxy-only" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if !strings.Contains(seen.Subscription, "port: "+strconv.Itoa(fake.SOCKSPort())) || !seen.RejectUDP || seen.MixedPort != free || seen.AllowLAN {
		t.Fatalf("mihomo options were not the engine route: %+v", seen)
	}
	if err := a.DeleteEngineProfile(summary.ID, summary.Revision); !errors.Is(err, errEngineInUse) {
		t.Fatal("deleted the engine carrying the connection")
	}
	if err := a.UseSubscriptionConnection(); err == nil {
		t.Fatal("switched route under a running connection")
	}

	// The engine dying is a failed session, and Stop still releases both.
	fake.exit()
	deadline := time.Now().Add(5 * time.Second)
	for manager.Snapshot().Phase != sessionmanager.Failed {
		if time.Now().After(deadline) {
			t.Fatalf("engine exit not reported: %+v", manager.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.closes != 1 || manager.HasOwner() || manager.Snapshot().Phase != sessionmanager.Disconnected {
		t.Fatal("stop did not confirm both releases")
	}

	if err := a.DeleteEngineProfile(summary.ID, summary.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := a.managedRequest(); !errors.Is(err, errSelectedEngineMissing) {
		t.Fatal("a deleted selection fell back to another route")
	}
	if err := a.UseSubscriptionConnection(); err != nil || a.GetSelectedEngineProfileID() != "" {
		t.Fatal("could not return to the subscription")
	}
}

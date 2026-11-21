package sessionmanager

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"whitevpn-desktop/internal/engineprofiles"
)

type fakeSession struct {
	mu       sync.Mutex
	stopErr  error
	stops    int
	ready    chan struct{}
	lifetime context.Context
}

func (s *fakeSession) WaitReady(ctx context.Context) error {
	if s.ready == nil {
		return nil
	}
	select {
	case <-s.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *fakeSession) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stops++
	return s.stopErr
}

type fakeBackend struct {
	mu           sync.Mutex
	session      *fakeSession
	starts       int
	preflightErr error
	startErr     error
	started      chan struct{}
}

func (b *fakeBackend) Preflight(context.Context, Plan) error { return b.preflightErr }
func (b *fakeBackend) Start(startup, lifetime context.Context, p ActivePlan) (Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.starts++
	if b.session != nil {
		b.session.lifetime = lifetime
	}
	if b.started != nil {
		close(b.started)
		b.started = nil
	}
	if b.session == nil {
		return nil, b.startErr
	}
	return b.session, b.startErr
}
func target() Plan {
	p := engineprofiles.Profile{Summary: engineprofiles.Summary{ID: "4823d941-6d8a-42e2-8d23-3d181e798a05", Name: "fixture", Kind: engineprofiles.SSH, Version: 1, Revision: 1}, Config: engineprofiles.Config{SSH: &engineprofiles.SSHConfig{Host: "localhost", Port: 22, Username: "fixture", AuthType: "password", Password: "manager-secret"}}}
	return Plan{Route: engineprofiles.RouteRef{Kind: "engine", ProfileID: p.ID}, Profile: p, Mode: "proxy"}
}

func TestConnectionLifetimeOutlivesStartupAndSnapshotHasNoCredentials(t *testing.T) {
	m := New(time.Second)
	s := &fakeSession{}
	b := &fakeBackend{session: s}
	if err := m.Register(engineprofiles.SSH, b); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Connect(ctx, target()); err != nil {
		t.Fatal(err)
	}
	cancel()
	if s.lifetime.Err() != nil {
		t.Fatal("startup request owns connection lifetime")
	}
	raw, _ := json.Marshal(m.Snapshot())
	if strings.Contains(string(raw), "manager-secret") || strings.Contains(string(raw), "config") {
		t.Fatal("snapshot contains credential config")
	}
	copy := m.Snapshot()
	copy.Route.ProfileID = "changed"
	if m.Snapshot().Route.ProfileID == "changed" {
		t.Fatal("snapshot aliases active plan")
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.lifetime.Err() == nil || m.HasOwner() || m.Snapshot().Phase != Disconnected {
		t.Fatal("confirmed stop did not release owner")
	}
}

func TestStopFailureRetainsOwnerAndBlocksNextStart(t *testing.T) {
	m := New(time.Second)
	s := &fakeSession{stopErr: errors.New("fixture stop failure")}
	b := &fakeBackend{session: s}
	_ = m.Register(engineprofiles.SSH, b)
	if err := m.Connect(context.Background(), target()); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background()); !errors.Is(err, ErrReleasePending) {
		t.Fatal("stop failure discarded")
	}
	if !m.HasOwner() || !m.Snapshot().ReleasePending {
		t.Fatal("uncertain ownership forgotten")
	}
	if err := m.Connect(context.Background(), target()); !errors.Is(err, ErrReleasePending) || b.starts != 1 {
		t.Fatal("another connection started before release")
	}
	s.mu.Lock()
	s.stopErr = nil
	s.mu.Unlock()
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect(context.Background(), target()); err != nil {
		t.Fatal(err)
	}
	_ = m.Stop(context.Background())
}

func TestTargetPreflightFailureLeavesActiveConnectionUntouched(t *testing.T) {
	m := New(time.Second)
	s := &fakeSession{}
	b := &fakeBackend{session: s}
	_ = m.Register(engineprofiles.SSH, b)
	if err := m.Connect(context.Background(), target()); err != nil {
		t.Fatal(err)
	}
	previous := m.Snapshot()
	b.preflightErr = errors.New("invalid target with manager-secret")
	if err := m.Connect(context.Background(), target()); !errors.Is(err, ErrPreflight) || strings.Contains(err.Error(), "manager-secret") {
		t.Fatal("preflight error not sanitized")
	}
	if s.stops != 0 || m.Snapshot().SessionID != previous.SessionID || m.Snapshot().Phase != Connected {
		t.Fatal("preflight changed old connection")
	}
	_ = m.Stop(context.Background())
}

func TestStopCancelsAndJoinsStartupBeforeReadiness(t *testing.T) {
	m := New(time.Second)
	ready := make(chan struct{})
	started := make(chan struct{})
	s := &fakeSession{ready: ready}
	b := &fakeBackend{session: s, started: started}
	_ = m.Register(engineprofiles.SSH, b)
	done := make(chan error, 1)
	go func() { done <- m.Connect(context.Background(), target()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not begin")
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("startup was not cancelled")
	}
	close(ready)
	if m.Snapshot().Phase != Disconnected || m.HasOwner() {
		t.Fatal("late readiness resurrected connection")
	}
}

func TestPartialStartupCleanupAndStaleFailure(t *testing.T) {
	m := New(time.Second)
	s := &fakeSession{stopErr: errors.New("not released")}
	b := &fakeBackend{session: s, startErr: errors.New("manager-secret")}
	_ = m.Register(engineprofiles.SSH, b)
	if err := m.Connect(context.Background(), target()); !errors.Is(err, ErrReleasePending) {
		t.Fatal("partial start lost cleanup error")
	}
	old := m.Snapshot()
	s.mu.Lock()
	s.stopErr = nil
	s.mu.Unlock()
	_ = m.Stop(context.Background())
	b.startErr = nil
	if err := m.Connect(context.Background(), target()); err != nil {
		t.Fatal(err)
	}
	current := m.Snapshot()
	if current.Generation <= old.Generation {
		t.Fatal("generation reused")
	}
	if m.ReportFailure(old.SessionID, old.Generation) || m.Snapshot().Phase != Connected {
		t.Fatal("stale failure changed new session")
	}
	if !m.ReportFailure(current.SessionID, current.Generation) || !m.HasOwner() {
		t.Fatal("current failure lost owner")
	}
	_ = m.Stop(context.Background())
}

func TestNativeProxyModeRejectedBeforePreflight(t *testing.T) {
	m := New(time.Second)
	p := target()
	p.Profile.Kind = engineprofiles.AmneziaWG
	p.Profile.Config = engineprofiles.Config{AmneziaWG: &engineprofiles.AmneziaWGConfig{Raw: "[Interface]"}}
	if err := m.Connect(context.Background(), p); err == nil || m.HasOwner() {
		t.Fatal("native silently downgraded to proxy")
	}
}

type blockingPreflight struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingPreflight) Preflight(ctx context.Context, p Plan) error {
	close(b.entered)
	<-b.release
	return ctx.Err()
}
func (b *blockingPreflight) Start(context.Context, context.Context, ActivePlan) (Session, error) {
	return nil, errors.New("must not start")
}

func TestCancelledPreflightDoesNotLeavePhantomOwner(t *testing.T) {
	m := New(time.Second)
	b := &blockingPreflight{entered: make(chan struct{}), release: make(chan struct{})}
	_ = m.Register(engineprofiles.SSH, b)
	done := make(chan error, 1)
	go func() { done <- m.Connect(context.Background(), target()) }()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("preflight did not begin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("preflight join deadline ignored")
	}
	if !m.HasOwner() || !m.Snapshot().ReleasePending {
		t.Fatal("unjoined preflight not pending")
	}
	close(b.release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("preflight cancellation lost")
	}
	if m.HasOwner() || m.Snapshot().ReleasePending || m.Snapshot().Phase != Disconnected {
		t.Fatal("completed preflight left phantom resources")
	}
}

type blockingBackend struct {
	entered chan struct{}
	release chan struct{}
	session *fakeSession
}

func (b *blockingBackend) Preflight(context.Context, Plan) error { return nil }
func (b *blockingBackend) Start(startup, lifetime context.Context, p ActivePlan) (Session, error) {
	close(b.entered)
	<-b.release
	b.session.lifetime = lifetime
	return b.session, nil
}

func TestStopDeadlineKeepsOwnershipUntilLateStartupIsCleaned(t *testing.T) {
	m := New(time.Second)
	b := &blockingBackend{entered: make(chan struct{}), release: make(chan struct{}), session: &fakeSession{}}
	_ = m.Register(engineprofiles.SSH, b)
	done := make(chan error, 1)
	go func() { done <- m.Connect(context.Background(), target()) }()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not begin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stop deadline ignored")
	}
	if !m.HasOwner() || !m.Snapshot().ReleasePending {
		t.Fatal("unjoined startup lost ownership")
	}
	close(b.release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("late startup reported successful connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not finish")
	}
	if m.HasOwner() || m.Snapshot().Phase != Disconnected {
		t.Fatal("late startup not cleaned")
	}
}

func TestFailureWhileConnectingCannotBeOverwrittenByReadiness(t *testing.T) {
	m := New(time.Second)
	ready := make(chan struct{})
	started := make(chan struct{})
	b := &fakeBackend{session: &fakeSession{ready: ready}, started: started}
	_ = m.Register(engineprofiles.SSH, b)
	done := make(chan error, 1)
	go func() { done <- m.Connect(context.Background(), target()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not begin")
	}
	state := m.Snapshot()
	if !m.ReportFailure(state.SessionID, state.Generation) {
		t.Fatal("current failure ignored")
	}
	close(ready)
	if err := <-done; err == nil {
		t.Fatal("failed startup became connected")
	}
	if m.Snapshot().Phase == Connected || m.HasOwner() {
		t.Fatal("failure was overwritten by readiness")
	}
}

// Package sessionmanager owns the main connection, including failed sessions
// whose network resources have not yet been confirmed released.
package sessionmanager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"whitevpn-desktop/internal/engineprofiles"
	"whitevpn-desktop/internal/session"
)

const (
	Disconnected                       = "disconnected"
	Connecting                         = "connecting"
	Connected                          = "connected"
	Stopping                           = "stopping"
	Failed                             = "failed"
	ReleasePending                     = "release-pending"
	Mihomo         engineprofiles.Kind = "mihomo"
)

var (
	ErrUnavailable    = errors.New("connection backend is unavailable")
	ErrPreflight      = errors.New("connection preflight failed")
	ErrStart          = errors.New("connection startup failed")
	ErrReadiness      = errors.New("connection readiness verification failed")
	ErrReleasePending = errors.New("previous connection resources have not been confirmed released")
	ErrBusy           = errors.New("a connection already owns the main route")
)

type Plan struct {
	Route   engineprofiles.RouteRef `json:"route"`
	Profile engineprofiles.Profile  `json:"-"`
	Mode    string                  `json:"mode"`
	Mihomo  *session.Options        `json:"-"`
}

func (p Plan) clone() Plan {
	p.Profile = p.Profile.Clone()
	if p.Mihomo != nil {
		options := p.Mihomo.Clone()
		p.Mihomo = &options
	}
	return p
}

func (p Plan) kind() engineprofiles.Kind {
	if p.Route.Kind == "mihomo" {
		return Mihomo
	}
	return p.Profile.Kind
}

func (p Plan) validate() error {
	if err := p.Route.Validate(); err != nil {
		return err
	}
	if p.Mode != "tun" && p.Mode != "proxy" && p.Mode != "proxy-only" {
		return fmt.Errorf("invalid connection mode")
	}
	if p.Route.Kind == "mihomo" {
		if p.Mihomo == nil || p.Profile.ID != "" || (p.Mode == "tun") != p.Mihomo.Tun.Enabled {
			return fmt.Errorf("invalid Mihomo plan")
		}
		return nil
	}
	if p.Route.ProfileID != p.Profile.ID {
		return fmt.Errorf("engine route does not match profile")
	}
	if err := p.Profile.Validate(); err != nil {
		return err
	}
	if !p.Profile.Kind.SOCKS() && p.Mode != "tun" {
		return fmt.Errorf("native engine requires TUN mode")
	}
	// A SOCKS engine is routed through Mihomo (Android EngineRuntimeYaml), so
	// its plan may carry the Mihomo options; a native engine never does.
	if p.Mihomo != nil && (!p.Profile.Kind.SOCKS() || (p.Mode == "tun") != p.Mihomo.Tun.Enabled) {
		return fmt.Errorf("invalid engine plan")
	}
	return nil
}

type ActivePlan struct {
	Plan
	SessionID  string
	Generation uint64
}

// Start's first context bounds startup only. Lifetime stays alive after Connect
// returns. On partial failure, return the Session with the error, so Stop can
// prove cleanup. A nil Session with an error promises no resources remain.
type Backend interface {
	Preflight(context.Context, Plan) error
	Start(startup, lifetime context.Context, plan ActivePlan) (Session, error)
}

// PreparedBackend resolves an immutable request under the control gate, before
// stopping the current owner. A resolved Mihomo fallback is an active route,
// never a rewrite of the user's stored selection.
type PreparedBackend interface {
	Prepare(context.Context, Plan) (Plan, error)
}

type Session interface {
	WaitReady(context.Context) error
	// Success means all owned resources are confirmed released, not merely that
	// a termination request was sent or a listener port disappeared.
	Stop(context.Context) error
}

type Snapshot struct {
	Phase           string                   `json:"phase"`
	SessionID       string                   `json:"sessionId,omitempty"`
	Generation      uint64                   `json:"generation"`
	Route           *engineprofiles.RouteRef `json:"route,omitempty"`
	Kind            engineprofiles.Kind      `json:"kind,omitempty"`
	ProfileRevision uint64                   `json:"profileRevision,omitempty"`
	Mode            string                   `json:"mode,omitempty"`
	ReleasePending  bool                     `json:"releasePending"`
	ErrorCode       string                   `json:"errorCode,omitempty"`
}

type owner struct {
	plan           ActivePlan
	session        Session
	cancelLifetime context.CancelFunc
}

type Manager struct {
	mu             sync.Mutex
	gate           chan struct{}
	backends       map[engineprofiles.Kind]Backend
	active         *owner
	state          Snapshot
	startupCancel  context.CancelFunc
	cleanupTimeout time.Duration
	updates        chan Snapshot
	controlEpoch   uint64
}

func New(cleanupTimeout time.Duration) *Manager {
	if cleanupTimeout <= 0 {
		cleanupTimeout = 5 * time.Second
	}
	return &Manager{gate: make(chan struct{}, 1), backends: map[engineprofiles.Kind]Backend{}, state: Snapshot{Phase: Disconnected}, cleanupTimeout: cleanupTimeout, updates: make(chan Snapshot, 1)}
}

func (m *Manager) Register(kind engineprofiles.Kind, backend Backend) error {
	if (!kind.Valid() && kind != Mihomo) || backend == nil {
		return fmt.Errorf("invalid connection backend")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.backends[kind]; exists {
		return fmt.Errorf("connection backend already registered")
	}
	m.backends[kind] = backend
	return nil
}

func (m *Manager) Snapshot() Snapshot       { m.mu.Lock(); defer m.mu.Unlock(); return m.snapshotLocked() }
func (m *Manager) Updates() <-chan Snapshot { return m.updates }

// HasOwner gates reset/restore even when the displayed connection has failed.
func (m *Manager) HasOwner() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active != nil || m.startupCancel != nil
}

func (m *Manager) Connect(ctx context.Context, target Plan) error {
	return m.connect(ctx, target, true)
}

func (m *Manager) ConnectNew(ctx context.Context, target Plan) error {
	return m.connect(ctx, target, false)
}

func (m *Manager) connect(ctx context.Context, target Plan, replace bool) error {
	m.mu.Lock()
	epoch := m.controlEpoch
	m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	target = target.clone()
	if err := target.validate(); err != nil {
		return err
	}
	if err := m.acquire(ctx); err != nil {
		return err
	}
	defer m.release()
	m.mu.Lock()
	if epoch != m.controlEpoch {
		m.mu.Unlock()
		return context.Canceled
	}
	if m.state.ReleasePending {
		m.mu.Unlock()
		return ErrReleasePending
	}
	if !replace && m.active != nil {
		m.mu.Unlock()
		return ErrBusy
	}
	backend := m.backends[target.kind()]
	if backend == nil {
		m.mu.Unlock()
		return ErrUnavailable
	}
	startup, cancel := context.WithCancel(ctx)
	m.startupCancel = cancel
	m.mu.Unlock()
	defer func() {
		cancel()
		m.mu.Lock()
		m.startupCancel = nil
		// Once an unjoined preflight returns without creating an owner, no
		// network mutation remains. A Stop timeout must not leave a phantom VPN.
		if m.active == nil && m.state.ReleasePending {
			m.state = Snapshot{Phase: Disconnected, Generation: m.state.Generation}
			m.publishLocked()
		}
		m.mu.Unlock()
	}()
	// Preflight never tears down a healthy old connection for an invalid target.
	var preflightErr error
	if preparer, ok := backend.(PreparedBackend); ok {
		kind := target.kind()
		target, preflightErr = preparer.Prepare(startup, target.clone())
		if preflightErr == nil {
			preflightErr = target.validate()
			if target.kind() != kind {
				preflightErr = ErrPreflight
			}
		}
		target = target.clone()
	} else {
		preflightErr = backend.Preflight(startup, target.clone())
	}
	if preflightErr != nil {
		if startup.Err() != nil {
			return startup.Err()
		}
		m.mu.Lock()
		if m.active == nil {
			m.state.Phase = Failed
			m.state.ErrorCode = "preflight-failed"
			m.publishLocked()
		}
		m.mu.Unlock()
		return ErrPreflight
	}
	if err := startup.Err(); err != nil {
		return err
	}
	if err := m.stopOwned(startup); err != nil {
		return err
	}
	if err := startup.Err(); err != nil {
		return err
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	m.mu.Lock()
	active := &owner{plan: ActivePlan{Plan: target, SessionID: uuid.NewString(), Generation: m.state.Generation + 1}, cancelLifetime: cancelLifetime}
	m.active = active
	route := target.Route
	m.state = Snapshot{Phase: Connecting, SessionID: active.plan.SessionID, Generation: active.plan.Generation, Route: &route, Kind: target.kind(), ProfileRevision: target.Profile.Revision, Mode: target.Mode}
	m.publishLocked()
	m.mu.Unlock()
	session, err := backend.Start(startup, lifetime, ActivePlan{Plan: target.clone(), SessionID: active.plan.SessionID, Generation: active.plan.Generation})
	m.mu.Lock()
	active.session = session
	m.mu.Unlock()
	if err != nil || startup.Err() != nil {
		return m.failedStart(active, startup, ErrStart, session == nil)
	}
	if session == nil {
		// A broken backend that reports success without a session cannot prove
		// ownership cleanup. Keep it blocked rather than guessing it is safe.
		m.mu.Lock()
		m.state.Phase = ReleasePending
		m.state.ReleasePending = true
		m.state.ErrorCode = "backend-contract"
		m.publishLocked()
		m.mu.Unlock()
		return ErrReleasePending
	}
	if err := session.WaitReady(startup); err != nil || startup.Err() != nil {
		return m.failedStart(active, startup, ErrReadiness, false)
	}
	m.mu.Lock()
	// Stop cancels startup while waiting for the serialized control operation.
	if startup.Err() != nil {
		m.mu.Unlock()
		return m.failedStart(active, startup, ErrReadiness, false)
	}
	m.state.Phase = Connected
	m.publishLocked()
	m.mu.Unlock()
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.controlEpoch++
	if m.startupCancel != nil {
		m.startupCancel()
	}
	m.mu.Unlock()
	if err := m.acquire(ctx); err != nil {
		m.mu.Lock()
		if m.active != nil || m.startupCancel != nil {
			m.state.Phase = ReleasePending
			m.state.ReleasePending = true
			m.state.ErrorCode = "stop-timeout"
			m.publishLocked()
		}
		m.mu.Unlock()
		return err
	}
	defer m.release()
	return m.stopOwned(ctx)
}

// WhileIdle serializes reset/restore with startup. Neither a failed owner nor
// unjoined preflight may lose files or recovery records under it.
func (m *Manager) WhileIdle(ctx context.Context, fn func() error) error {
	if m.HasOwner() {
		return ErrBusy
	}
	if err := m.acquire(ctx); err != nil {
		return err
	}
	defer m.release()
	m.mu.Lock()
	m.controlEpoch++
	busy := m.active != nil || m.startupCancel != nil || m.state.ReleasePending
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.controlEpoch++; m.mu.Unlock() }()
	if busy {
		return ErrBusy
	}
	return fn()
}

func (m *Manager) failedStart(active *owner, startup context.Context, reason error, noResources bool) error {
	if noResources {
		active.cancelLifetime()
		m.mu.Lock()
		m.active = nil
		m.state.Phase = Failed
		m.state.ReleasePending = false
		m.state.ErrorCode = "startup-failed"
		if errors.Is(startup.Err(), context.Canceled) {
			m.state.Phase = Disconnected
			m.state.ErrorCode = ""
		}
		m.publishLocked()
		m.mu.Unlock()
	} else {
		cleanup, cancel := context.WithTimeout(context.Background(), m.cleanupTimeout)
		err := m.stopOwned(cleanup)
		cancel()
		if err != nil {
			return ErrReleasePending
		}
		if startup.Err() == nil || errors.Is(startup.Err(), context.DeadlineExceeded) {
			m.mu.Lock()
			m.state.Phase = Failed
			m.state.ErrorCode = "startup-failed"
			m.publishLocked()
			m.mu.Unlock()
		}
	}
	if err := startup.Err(); err != nil {
		return err
	}
	return reason
}

// Called only while holding the control gate. Backend resource calls never run
// under the snapshot mutex, so Snapshot/Stop cancellation remain responsive.
func (m *Manager) stopOwned(ctx context.Context) error {
	m.mu.Lock()
	active := m.active
	if active == nil {
		if m.state.ReleasePending {
			m.state = Snapshot{Phase: Disconnected, Generation: m.state.Generation}
			m.publishLocked()
		}
		m.mu.Unlock()
		return nil
	}
	m.state.Phase = Stopping
	m.publishLocked()
	m.mu.Unlock()
	if active.session == nil {
		m.mu.Lock()
		m.state.Phase = ReleasePending
		m.state.ReleasePending = true
		m.state.ErrorCode = "cleanup-unconfirmed"
		m.publishLocked()
		m.mu.Unlock()
		return ErrReleasePending
	}
	if err := active.session.Stop(ctx); err != nil {
		m.mu.Lock()
		m.state.Phase = ReleasePending
		m.state.ReleasePending = true
		m.state.ErrorCode = "cleanup-unconfirmed"
		m.publishLocked()
		m.mu.Unlock()
		return ErrReleasePending
	}
	active.cancelLifetime()
	m.mu.Lock()
	m.active = nil
	m.state = Snapshot{Phase: Disconnected, Generation: active.plan.Generation}
	m.publishLocked()
	m.mu.Unlock()
	return nil
}

// Ignore failure events from an older process/session after a successful switch.
// Error details stay in the adapter's sanitized diagnostics, not public state.
func (m *Manager) ReportFailure(sessionID string, generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil || m.active.plan.SessionID != sessionID || m.active.plan.Generation != generation {
		return false
	}
	if m.startupCancel != nil {
		m.startupCancel()
	}
	m.state.Phase = Failed
	m.state.ReleasePending = true
	m.state.ErrorCode = "session-failed"
	m.publishLocked()
	return true
}

// Matches guards adapter callbacks without exposing its credential-bearing plan.
func (m *Manager) Matches(sessionID string, generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active != nil && m.active.plan.SessionID == sessionID && m.active.plan.Generation == generation && !m.state.ReleasePending && m.state.Phase != Stopping
}

func (m *Manager) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (m *Manager) release() { <-m.gate }

func (m *Manager) snapshotLocked() Snapshot {
	s := m.state
	if s.Route != nil {
		ref := *s.Route
		s.Route = &ref
	}
	return s
}
func (m *Manager) publishLocked() {
	s := m.snapshotLocked()
	select {
	case m.updates <- s:
	default:
		select {
		case <-m.updates:
		default:
		}
		select {
		case m.updates <- s:
		default:
		}
	}
}

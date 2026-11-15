// Package api implements the versioned REST surface over application
// services. Handlers never touch protocol types; they call a Service.
package api

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/angga0x3/whatscore/core/session"
)

// ErrNotFound is returned for unknown session ids.
var ErrNotFound = errors.New("api: session not found")

// ErrInvalidInput is returned for unusable request data.
var ErrInvalidInput = errors.New("api: invalid input")

// SessionView is the REST representation of a session (openapi Session).
type SessionView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Service is the application boundary the handlers depend on.
type Service interface {
	ListSessions(ctx context.Context, status string) ([]SessionView, error)
	GetSession(ctx context.Context, id string) (SessionView, error)
	CreateSession(ctx context.Context, name string) (SessionView, error)
	DeleteSession(ctx context.Context, id string) error
	ConnectSession(ctx context.Context, id string) error
	DisconnectSession(ctx context.Context, id string) error
}

// Manager is an in-memory Service over core/session instances. It is the
// reference implementation for tests and single-process deployments; a
// database-backed service implements the same interface.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*managedSession
	now      func() time.Time
	newID    func() (string, error)
	factory  func(name string) (*session.Session, error)
}

type managedSession struct {
	view    SessionView
	session *session.Session
	name    string
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager) error

// WithSessionFactory overrides how a new core/session is built.
func WithSessionFactory(factory func(name string) (*session.Session, error)) ManagerOption {
	return func(m *Manager) error {
		if factory == nil {
			return fmt.Errorf("%w: nil session factory", ErrInvalidInput)
		}
		m.factory = factory
		return nil
	}
}

// NewManager returns an empty Manager.
func NewManager(opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		sessions: make(map[string]*managedSession),
		now:      time.Now,
		newID:    newSessionID,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ListSessions returns sessions in stable id order, optionally filtered.
func (m *Manager) ListSessions(_ context.Context, status string) ([]SessionView, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]SessionView, 0, len(m.sessions))
	for _, entry := range m.sessions {
		if status != "" && entry.view.Status != status {
			continue
		}
		out = append(out, entry.view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GetSession returns one session.
func (m *Manager) GetSession(_ context.Context, id string) (SessionView, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.sessions[id]
	if !ok {
		return SessionView{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return entry.view, nil
}

// CreateSession registers a new session in STOPPED state.
func (m *Manager) CreateSession(_ context.Context, name string) (SessionView, error) {
	if err := validateName(name); err != nil {
		return SessionView{}, err
	}
	id, err := m.newID()
	if err != nil {
		return SessionView{}, fmt.Errorf("api: session id: %w", err)
	}

	var sess *session.Session
	if m.factory != nil {
		sess, err = m.factory(id)
		if err != nil {
			return SessionView{}, fmt.Errorf("api: build session: %w", err)
		}
	}
	now := m.now()
	view := SessionView{ID: id, Name: name, Status: "STOPPED", CreatedAt: now, UpdatedAt: now}

	m.mu.Lock()
	m.sessions[id] = &managedSession{view: view, session: sess, name: name}
	m.mu.Unlock()
	return view, nil
}

// DeleteSession removes a session, stopping it first when it is running.
func (m *Manager) DeleteSession(ctx context.Context, id string) error {
	m.mu.Lock()
	entry, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if entry.session != nil {
		if err := entry.session.Stop(ctx); err != nil && !errors.Is(err, session.ErrSessionClosed) {
			return fmt.Errorf("api: stop session: %w", err)
		}
	}
	return nil
}

// ConnectSession starts the session connection.
func (m *Manager) ConnectSession(ctx context.Context, id string) error {
	entry, err := m.entry(id)
	if err != nil {
		return err
	}
	if entry.session == nil {
		return m.setStatus(id, "CONNECTED")
	}
	if err := entry.session.Connect(ctx); err != nil {
		if statusErr := m.setStatus(id, statusOf(entry.session, "ERROR")); statusErr != nil {
			return fmt.Errorf("api: connect: %w (status: %v)", err, statusErr)
		}
		return fmt.Errorf("api: connect: %w", err)
	}
	return m.setStatus(id, "CONNECTED")
}

// DisconnectSession stops the session connection without deleting it.
func (m *Manager) DisconnectSession(ctx context.Context, id string) error {
	entry, err := m.entry(id)
	if err != nil {
		return err
	}
	if entry.session == nil {
		return m.setStatus(id, "DISCONNECTED")
	}
	if err := entry.session.Disconnect(ctx); err != nil {
		return fmt.Errorf("api: disconnect: %w", err)
	}
	return m.setStatus(id, "DISCONNECTED")
}

func (m *Manager) entry(id string) (*managedSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return entry, nil
}

func (m *Manager) setStatus(id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	entry.view.Status = status
	entry.view.UpdatedAt = m.now()
	return nil
}

func statusOf(s *session.Session, fallback string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, err := s.State(ctx)
	if err != nil {
		return fallback
	}
	return state.String()
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidInput)
	}
	if len(name) > 100 {
		return fmt.Errorf("%w: name longer than 100 bytes", ErrInvalidInput)
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 {
			return fmt.Errorf("%w: name contains a control character", ErrInvalidInput)
		}
	}
	return nil
}

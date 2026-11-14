package mfa

import (
	"context"
	"sync"

	"github.com/kadeessh/kadeessh/internal/session"
)

type sessionStateCtxKey struct{}

// SessionState carries the complete MFA state for one SSH connection.
type SessionState struct {
	mu            sync.RWMutex
	config        *Config
	username      string
	decision      AuthDecision
	flow          PrimaryFlow
	authenticated bool
}

type sessionStateSnapshot struct {
	config        *Config
	username      string
	decision      AuthDecision
	flow          PrimaryFlow
	authenticated bool
}

func stateFromContext(ctx context.Context) *SessionState {
	state, _ := ctx.Value(sessionStateCtxKey{}).(*SessionState)
	return state
}

func stateForSession(ctx session.Context) *SessionState {
	if state := stateFromContext(ctx); state != nil {
		return state
	}
	state := new(SessionState)
	ctx.SetValue(sessionStateCtxKey{}, state)
	return state
}

func (s *SessionState) snapshot() sessionStateSnapshot {
	if s == nil {
		return sessionStateSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sessionStateSnapshot{
		config:        s.config,
		username:      s.username,
		decision:      s.decision,
		flow:          s.flow,
		authenticated: s.authenticated,
	}
}

func setDecision(ctx session.Context, config *Config, flow PrimaryFlow, decision AuthDecision) {
	state := stateForSession(ctx)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.config = config
	state.flow = flow
	state.decision = decision
}

func markAuthenticated(ctx session.Context) {
	state := stateForSession(ctx)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.authenticated = true
}

// ConfigFromCtx returns the MFA config attached to this connection.
func ConfigFromCtx(ctx context.Context) *Config {
	return stateFromContext(ctx).snapshot().config
}

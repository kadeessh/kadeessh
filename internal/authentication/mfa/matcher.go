package mfa

import (
	"context"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchMFAStatus{})
}

// MFAStatus classifies a user's MFA enrollment posture on the current
// session, as observed by the auth-layer decorator.
type MFAStatus string

const (
	// StatusEnrolled means the user has a valid enrollment record and
	// successfully completed a second-factor challenge (or the sk-*
	// primary factor satisfied MFA on its own).
	StatusEnrolled MFAStatus = "enrolled"

	// StatusUnenrolled means the user has no factors registered (or
	// has no record at all).
	StatusUnenrolled MFAStatus = "unenrolled"

	// StatusPending means the user has been seen before (FirstSeenAt
	// is set) but has not yet completed enrollment. Distinct from
	// StatusUnenrolled only when the operator wants to distinguish
	// first-timers from repeat lag.
	StatusPending MFAStatus = "pending"
)

// MatchMFAStatus is an actor matcher that consults the MFA
// enrollment record stashed on the session context by the decorator.
// Registered as ssh.actor_matchers.mfa_status.
//
// Values are matched with OR semantics: a session matches if its
// current status equals ANY of the listed values. An empty list
// matches nothing.
type MatchMFAStatus struct {
	// Statuses is the accepted status list ("enrolled",
	// "unenrolled", "pending").
	Statuses []string `json:"statuses,omitempty"`

	set    map[MFAStatus]struct{}
	logger *zap.Logger
}

// CaddyModule identifies this module to Caddy.
func (MatchMFAStatus) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.mfa_status",
		New: func() caddy.Module { return new(MatchMFAStatus) },
	}
}

// Provision validates and indexes the status list.
func (m *MatchMFAStatus) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.set = make(map[MFAStatus]struct{}, len(m.Statuses))
	for _, s := range m.Statuses {
		switch MFAStatus(s) {
		case StatusEnrolled, StatusUnenrolled, StatusPending:
			m.set[MFAStatus(s)] = struct{}{}
		default:
			return fmt.Errorf("mfa_status: unknown status %q", s)
		}
	}
	return nil
}

// ShouldAct implements the actor-matcher contract.
func (m MatchMFAStatus) ShouldAct(sctx session.ActorMatchingContext) bool {
	got := statusFromCtx(sctx)
	_, ok := m.set[got]
	return ok
}

// statusFromCtx classifies the current session. If no record is on
// the context, the user is treated as StatusUnenrolled (this covers
// deployments where MFA is not configured — matchers using
// mfa_status will simply not match).
func statusFromCtx(sctx session.ActorMatchingContext) MFAStatus {
	return statusFromContext(sctx.Context())
}

func statusFromContext(ctx context.Context) MFAStatus {
	state := stateFromContext(ctx).snapshot()
	if state.authenticated {
		return StatusEnrolled
	}
	rec := state.decision.Record
	if rec == nil {
		return StatusUnenrolled
	}
	if rec.Enrolled() {
		return StatusEnrolled
	}
	if !rec.FirstSeenAt.IsZero() {
		return StatusPending
	}
	return StatusUnenrolled
}

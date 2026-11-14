package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PrimaryFlow identifies the primary authentication method that succeeded.
type PrimaryFlow string

const (
	FlowPublicKey   PrimaryFlow = "public_key"
	FlowPassword    PrimaryFlow = "password_auth"
	FlowInteractive PrimaryFlow = "interactive"
)

// DecisionAction is the next authentication action after primary success.
type DecisionAction int

const (
	ActionAllow DecisionAction = iota
	ActionVerify
	ActionEnroll
)

// DecisionReason explains why an action was selected.
type DecisionReason string

const (
	ReasonGracePeriod      DecisionReason = "grace_period"
	ReasonPrimaryFactor    DecisionReason = "primary_factor"
	ReasonEnrolled         DecisionReason = "enrolled"
	ReasonEnrollmentNeeded DecisionReason = "enrollment_needed"
)

// AuthEvent is the callback-independent input to the MFA decision service.
type AuthEvent struct {
	Username          string
	Flow              PrimaryFlow
	PrimaryKeyType    string
	PrimaryKeyNoTouch bool
}

// AuthDecision is the complete result of MFA policy evaluation.
type AuthDecision struct {
	Action             DecisionAction
	Reason             DecisionReason
	Mode               EnforcementMode
	Record             *EnrollmentRecord
	PrimaryKeyType     string
	EnrollmentDeadline time.Time
}

// PrimaryFactorPolicy decides whether a primary credential also satisfies MFA.
type PrimaryFactorPolicy interface {
	SatisfiesMFA(AuthEvent) bool
}

// SKTouchPolicy accepts touch-required OpenSSH security-key credentials.
type SKTouchPolicy struct {
	Enabled bool
}

func (p SKTouchPolicy) SatisfiesMFA(event AuthEvent) bool {
	if !p.Enabled || event.Flow != FlowPublicKey {
		return false
	}
	return isSKKey(event.PrimaryKeyType) && !event.PrimaryKeyNoTouch
}

var (
	errCanonicalUsername = errors.New("mfa: authenticated user has no canonical username")
	errEnrollmentStorage = errors.New("mfa: enrollment storage failure")
)

// LockoutError reports an active MFA verification lockout.
type LockoutError struct {
	Until time.Time
}

func (e *LockoutError) Error() string {
	return "mfa: too many recent failures; try again later"
}

// Service evaluates MFA policy independently from the SSH callback transport.
type Service struct {
	policy              Policy
	store               EnrollmentStore
	serverName          string
	primaryFactorPolicy PrimaryFactorPolicy
	now                 func() time.Time
}

func newService(policy Policy, store EnrollmentStore, serverName string) *Service {
	skEnabled := policy.SkSatisfiesMFA != nil && *policy.SkSatisfiesMFA
	return &Service{
		policy:              policy,
		store:               store,
		serverName:          serverName,
		primaryFactorPolicy: SKTouchPolicy{Enabled: skEnabled},
		now:                 time.Now,
	}
}

// Decide returns the next MFA action and the state used to reach it.
func (s *Service) Decide(ctx context.Context, event AuthEvent) (AuthDecision, error) {
	var decision AuthDecision
	if event.Username == "" {
		return decision, errCanonicalUsername
	}
	decision.PrimaryKeyType = event.PrimaryKeyType
	if s.primaryFactorPolicy.SatisfiesMFA(event) {
		decision.Action = ActionAllow
		decision.Reason = ReasonPrimaryFactor
		return decision, nil
	}

	now := s.now()
	rec, _, err := s.store.Load(ctx, s.serverName, event.Username)
	if err != nil {
		return decision, fmt.Errorf("%w: loading record: %v", errEnrollmentStorage, err)
	}
	decision.Record = rec
	if s.policy.LockedOut(rec, now) {
		return decision, &LockoutError{Until: rec.FailedAttempts.LockedUntil}
	}

	decision.Mode = s.policy.EnforcementFor(rec, now)
	if rec.Enrolled() {
		decision.Action = ActionVerify
		decision.Reason = ReasonEnrolled
		return decision, nil
	}

	rec, err = s.recordFirstSeen(ctx, event.Username, now)
	if err != nil {
		return decision, err
	}
	decision.Record = rec

	// Enrollment may have completed between the initial load and the
	// storage-locked update.
	if rec.Enrolled() {
		decision.Mode = ModeRequire
		decision.Action = ActionVerify
		decision.Reason = ReasonEnrolled
		return decision, nil
	}

	decision.Mode = s.policy.EnforcementFor(rec, now)
	decision.EnrollmentDeadline = rec.FirstSeenAt.Add(time.Duration(s.policy.GracePeriod))
	if decision.Mode == ModeNudge {
		decision.Action = ActionAllow
		decision.Reason = ReasonGracePeriod
		return decision, nil
	}

	decision.Action = ActionEnroll
	decision.Reason = ReasonEnrollmentNeeded
	return decision, nil
}

func (s *Service) recordFirstSeen(ctx context.Context, username string, now time.Time) (*EnrollmentRecord, error) {
	var latest *EnrollmentRecord
	err := s.store.Update(ctx, s.serverName, username, func(rec *EnrollmentRecord) *EnrollmentRecord {
		if rec == nil {
			rec = &EnrollmentRecord{}
		}
		if rec.FirstSeenAt.IsZero() {
			rec.FirstSeenAt = now
			latest = rec
			return rec
		}
		latest = rec
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: recording first seen: %v", errEnrollmentStorage, err)
	}
	if latest == nil {
		return nil, fmt.Errorf("%w: first-seen update returned no record", errEnrollmentStorage)
	}
	return latest, nil
}

func isSKKey(keyType string) bool {
	return strings.HasPrefix(keyType, "sk-")
}

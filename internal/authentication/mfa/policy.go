package mfa

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// EnforcementMode describes how the decorator handles unenrolled users.
type EnforcementMode int

const (
	// ModeNudge is the default: unenrolled users are allowed through
	// after the primary factor and a grace-bypass audit event is
	// emitted. Applied while the user is still inside their grace
	// window.
	ModeNudge EnforcementMode = iota

	// ModeRequire forces unenrolled users through the enrollment
	// wizard (over keyboard-interactive) before any real session.
	// Applied after the grace window elapses or when GracePeriod is
	// zero.
	ModeRequire
)

// Policy is the configurable enforcement policy for the MFA decorator.
// All fields have safe defaults so an empty {"mfa": {}} block is a
// valid config.
type Policy struct {
	// GracePeriod is the duration after a user's first primary-factor
	// success during which they may still connect without enrolling.
	// After it elapses, the mode flips to ModeRequire for that user.
	// Zero means no grace: unenrolled users must enroll on first
	// login. A negative value is rejected at Provision time. Default:
	// 30 days.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// SkSatisfiesMFA, when true, treats an SSH-level primary auth
	// with a hardware-backed key (sk-ssh-ed25519@openssh.com,
	// sk-ecdsa-sha2-nistp256@openssh.com, and the corresponding
	// cert variants) as fully authenticated and skips the second
	// factor even for enrolled users. Keys carrying
	// no-touch-required do not qualify. Default: true.
	SkSatisfiesMFA *bool `json:"sk_satisfies_mfa,omitempty"`

	// MaxFailedAttempts is the number of failed second-factor
	// verifications tolerated within the attempts window before a
	// lockout is applied. Default: 5.
	MaxFailedAttempts int `json:"max_failed_attempts,omitempty"`

	// AttemptsWindow is the rolling window over which failures are
	// counted. Default: 15 minutes.
	AttemptsWindow caddy.Duration `json:"attempts_window,omitempty"`

	// LockoutDuration is how long the user is denied after crossing
	// MaxFailedAttempts. Default: 30 seconds.
	LockoutDuration caddy.Duration `json:"lockout_duration,omitempty"`

	gracePeriodSet bool
}

// UnmarshalJSON distinguishes an omitted grace_period from an explicit
// "0s", which means immediate enforcement.
func (p *Policy) UnmarshalJSON(data []byte) error {
	type policyAlias Policy
	var decoded policyAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*p = Policy(decoded)
	_, p.gracePeriodSet = fields["grace_period"]
	return nil
}

// applyDefaults fills unset fields with the shipped defaults.
func (p *Policy) applyDefaults() {
	if !p.gracePeriodSet && p.GracePeriod == 0 {
		p.GracePeriod = caddy.Duration(30 * 24 * time.Hour)
	}
	if p.SkSatisfiesMFA == nil {
		v := true
		p.SkSatisfiesMFA = &v
	}
	if p.MaxFailedAttempts == 0 {
		p.MaxFailedAttempts = 5
	}
	if p.AttemptsWindow == 0 {
		p.AttemptsWindow = caddy.Duration(15 * time.Minute)
	}
	if p.LockoutDuration == 0 {
		p.LockoutDuration = caddy.Duration(30 * time.Second)
	}
}

func (p Policy) validate() error {
	if p.GracePeriod < 0 {
		return errors.New("mfa: grace_period cannot be negative")
	}
	if p.AttemptsWindow < 0 {
		return errors.New("mfa: attempts_window cannot be negative")
	}
	if p.LockoutDuration < 0 {
		return errors.New("mfa: lockout_duration cannot be negative")
	}
	if p.MaxFailedAttempts < 0 {
		return errors.New("mfa: max_failed_attempts cannot be negative")
	}
	return nil
}

// EnforcementFor returns the enforcement mode for a user at time now,
// given their (possibly nil) enrollment record. The record's
// FirstSeenAt anchor is used to determine whether the grace period
// has elapsed.
//
// An enrolled user always returns ModeRequire — enrollment implies
// enforcement, with no per-user opt-out.
func (p Policy) EnforcementFor(rec *EnrollmentRecord, now time.Time) EnforcementMode {
	if rec.Enrolled() {
		return ModeRequire
	}
	grace := time.Duration(p.GracePeriod)
	if grace <= 0 {
		return ModeRequire
	}
	if rec == nil || rec.FirstSeenAt.IsZero() {
		// First time we've seen this user: they are still within the
		// grace window by definition.
		return ModeNudge
	}
	if now.Sub(rec.FirstSeenAt) >= grace {
		return ModeRequire
	}
	return ModeNudge
}

// LockedOut reports whether the user is currently within a rate-limit
// lockout. Callers should short-circuit verification when true.
func (p Policy) LockedOut(rec *EnrollmentRecord, now time.Time) bool {
	if rec == nil {
		return false
	}
	return !rec.FailedAttempts.LockedUntil.IsZero() && now.Before(rec.FailedAttempts.LockedUntil)
}

// NextLockoutState computes the counter/lockout transition after a
// single failed attempt at time now. It returns the new failure state
// but does not persist; the store's RecordFailure applies this
// transition atomically under the shared lock.
func (p Policy) NextLockoutState(prev FailedAttempts, now time.Time) FailedAttempts {
	window := time.Duration(p.AttemptsWindow)
	// Roll the window: if the previous window has fully elapsed, reset
	// the counter before incrementing.
	if prev.WindowStart.IsZero() || (window > 0 && now.Sub(prev.WindowStart) > window) {
		prev.WindowStart = now
		prev.Count = 0
	}
	prev.Count++
	if p.MaxFailedAttempts > 0 && prev.Count >= p.MaxFailedAttempts {
		prev.LockedUntil = now.Add(time.Duration(p.LockoutDuration))
	}
	return prev
}

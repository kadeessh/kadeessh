// Package mfa implements Multi-Factor Authentication for Kadeessh.
//
// MFA is layered on top of the existing primary auth flows (public_key,
// password_auth, interactive) as a decorator. When the primary flow
// succeeds, mfa.Config.Wrap* wraps the returned callback so that:
//
//   - If the user has an enrollment record, the callback returns
//     golang.org/x/crypto/ssh.PartialSuccessError to force a
//     keyboard-interactive round trip that verifies a TOTP code or
//     recovery code.
//   - If the user is unenrolled and the grace period has not yet
//     expired, the callback returns the primary permissions and emits
//     a structured grace-bypass audit event.
//   - If the user is unenrolled and the grace period has expired, the
//     callback returns PartialSuccessError with a keyboard-interactive
//     enrollment challenge that walks the user through TOTP setup
//     before granting access.
//
// The primary flow modules themselves are unchanged; the decorator sits
// one layer up, in authentication.Config, and preserves back-compat with
// deployments that do not set an "mfa" block.
package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ValidateScopeComponent rejects values that could escape the intended
// Caddy-storage or filesystem namespace.
func ValidateScopeComponent(kind, value string) error {
	if value == "" {
		return fmt.Errorf("mfa: %s is required", kind)
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`+"\x00") {
		return fmt.Errorf("mfa: invalid %s %q", kind, value)
	}
	return nil
}

// EnrollmentStore persists MFA enrollment records, keyed by
// (serverName, username). Implementations must serialize concurrent
// mutations through Update so that multiple replicas backed by the
// same storage (filesystem, S3, etc.) cannot race on mutable factor
// state, failed-attempt counters, or recovery-code used markers.
type EnrollmentStore interface {
	// Load returns the enrollment record for (server, username). ok is
	// false if no record exists. Any I/O or unmarshal error is
	// surfaced.
	Load(ctx context.Context, server, username string) (rec *EnrollmentRecord, ok bool, err error)

	// Update atomically reads the current record (nil if none exists),
	// passes it to mutate, and persists whatever mutate returns. A nil
	// return leaves the record untouched. The mutate func is invoked
	// while a shared-storage lock is held on (server, username), so
	// implementations must be lock-friendly: quick, non-blocking, and
	// must not call back into the store on the same key.
	//
	// mutate receives a fresh copy of the record; callers may mutate
	// in place and return it, or return a fully new record. The
	// returned record's Server and Username fields are set by the
	// store before persistence.
	Update(ctx context.Context, server, username string, mutate func(*EnrollmentRecord) *EnrollmentRecord) error

	// Delete removes the record for (server, username). Missing
	// records are not an error.
	Delete(ctx context.Context, server, username string) error

	// List returns the usernames enrolled under the given server.
	List(ctx context.Context, server string) ([]string, error)

	// SealKey returns the seal key used to encrypt TOTP secrets at
	// rest. Provisioning generates one if none exists in storage.
	SealKey() [32]byte
}

// SecondFactor is a pluggable factor module loaded under the
// ssh.authentication.mfa.factors namespace. A factor participates in
// both enrollment (generating credentials the user must retain) and
// verification (checking a response against the persisted record).
//
// A response with a leading "r-" prefix is stripped and routed to the
// recovery_codes factor by convention; other factors receive the
// verbatim response.
type SecondFactor interface {
	// Name returns the short identifier used in logs and challenge
	// prompts. Should be stable across versions.
	Name() string

	// Enroll generates fresh secret material for the given username
	// and returns:
	//   - a per-factor blob to persist inside the EnrollmentRecord
	//     (implementations own the schema).
	//   - a human-visible artifact rendered by the enrollment wizard
	//     (e.g. otpauth:// URI + ASCII QR, or the plaintext recovery
	//     code list).
	// The material must not be persisted here; the caller decides when
	// to commit after the user confirms.
	Enroll(ctx context.Context, username string) (blob FactorBlob, artifact EnrollmentArtifact, err error)

	// Verify checks response against the persisted blob. It returns
	// (true, updatedBlob, nil) on success, (false, nil, nil) on a
	// clean mismatch, and (false, nil, err) for I/O or corruption
	// errors. Replay-sensitive factors must return updatedBlob on
	// success. The caller verifies and persists that state inside one
	// EnrollmentStore.Update transaction before granting access.
	Verify(ctx context.Context, username string, blob FactorBlob, response string) (ok bool, updated FactorBlob, err error)

	// Prompt returns the keyboard-interactive prompt line the verify
	// challenge should show, e.g. "6-digit authenticator code:".
	Prompt() string
}

// FactorBlob is the per-factor persistence payload embedded in the
// EnrollmentRecord. Concrete factor modules define their own struct
// and register a JSON encoding. FactorBlob is JSON-marshalled as-is
// inside the record's Factors map.
type FactorBlob any

// SealKeyReceiver is an optional interface a factor may implement to
// receive the store's seal key at provision time. The TOTP factor
// uses it to seal secrets at rest; recovery codes do not need it
// (codes are hashed, not encrypted).
type SealKeyReceiver interface {
	SetSealKey(k [32]byte)
}

// EnrollmentArtifact is the material shown to the user by the
// enrollment wizard. Factors may attach one or more of:
//   - Instructions: a short explanation shown before the payload.
//   - OtpauthURI: an otpauth:// URI the user can paste into their app.
//   - QRCode: ASCII-rendered QR code (typically wrapping OtpauthURI).
//   - Codes: plaintext recovery codes to write down.
type EnrollmentArtifact struct {
	Instructions string
	OtpauthURI   string
	QRCode       string
	Codes        []string
}

// EnrollmentRecord is the persisted-per-user MFA state. Only Sealed
// material is written to storage; the Unsealed fields are populated
// on Load by the store's seal helper and are never persisted.
type EnrollmentRecord struct {
	// Version is the on-disk schema version. Bumped whenever the
	// serialization format changes in a backwards-incompatible way.
	Version int `json:"version"`

	// Server is the SSH server name this record is scoped to. Kept in
	// the record for cross-checking after Load.
	Server string `json:"server"`

	// Username is the SSH login name.
	Username string `json:"username"`

	// Provider is the primary auth provider that authenticated this
	// user at enrollment time (e.g. "static", "os"). Advisory; used
	// by admin CLI to display provenance.
	Provider string `json:"provider,omitempty"`

	// EnrolledAt is when the wizard confirmed setup.
	EnrolledAt time.Time `json:"enrolled_at"`

	// LastUsedAt is when the second factor was last successfully
	// verified.
	LastUsedAt time.Time `json:"last_used_at,omitempty"`

	// FirstSeenAt is when the user first authenticated with the
	// primary factor. Grace-period math is anchored here.
	FirstSeenAt time.Time `json:"first_seen_at,omitempty"`

	// Factors is a map of factor-name -> raw JSON blob. The store
	// unmarshals into per-factor types via the factor registry.
	Factors map[string]json.RawMessage `json:"factors,omitempty"`

	// FailedAttempts is the rate-limit counter, incremented via the
	// storage-locked RecordFailure API and reset via ResetFailures.
	FailedAttempts FailedAttempts `json:"failed_attempts,omitempty"`
}

// FailedAttempts tracks recent verification failures for rate limiting.
// The window rolls: if the current time is more than window past
// WindowStart, the counter is treated as zero on the next update.
type FailedAttempts struct {
	WindowStart time.Time `json:"window_start,omitempty"`
	Count       int       `json:"count,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

// Enrolled reports whether the record represents a completed
// enrollment (at least one factor blob is present).
func (r *EnrollmentRecord) Enrolled() bool {
	return r != nil && len(r.Factors) > 0
}

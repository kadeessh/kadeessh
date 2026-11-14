package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

// ------------------------------------------------------------------
// Verify challenge — used when the user is already enrolled. One KI
// round asking for a 6-digit code (or an "r-<code>" recovery code).

func (c *Config) verifyChallenge(sctx session.Context, primaryPerms *gossh.Permissions) func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		username := UsernameFromCtx(sctx)
		rec := stateFromContext(sctx).snapshot().decision.Record
		if rec == nil || !rec.Enrolled() {
			// Shouldn't happen — Service.Decide gated on Enrolled() —
			// but guard defensively.
			return nil, errors.New("mfa: no enrollment record")
		}

		answers, err := challenge(
			username,
			"Multi-factor authentication required.",
			[]string{c.verifyPrompt()},
			[]bool{false},
		)
		if err != nil {
			return nil, err
		}
		if len(answers) != 1 {
			return nil, errors.New("mfa: expected one answer")
		}
		response := strings.TrimSpace(answers[0])
		if response == "" {
			return nil, errors.New("mfa: empty response")
		}

		ok, factorName, err := c.verifyAndCommit(sctx, username, response)
		if err != nil {
			var lockout *LockoutError
			if errors.As(err, &lockout) {
				c.log.Info("mfa audit event",
					zap.String("event", "mfa.lockout_denied"),
					zap.String("user", username),
					zap.String("remote_address", remoteAddress(conn)),
					zap.Time("locked_until", lockout.Until),
				)
				return nil, lockout
			}
			c.log.Warn("mfa audit event",
				zap.String("event", "mfa.verification_error"),
				zap.String("user", username),
				zap.String("remote_address", remoteAddress(conn)),
				zap.Error(err),
			)
			c.registerFailure(sctx, username)
			return nil, errors.New("mfa: verification failed")
		}
		if !ok {
			c.log.Info("mfa audit event",
				zap.String("event", "mfa.verification_failed"),
				zap.String("user", username),
				zap.String("remote_address", remoteAddress(conn)),
			)
			c.registerFailure(sctx, username)
			return nil, errors.New("mfa: invalid code")
		}

		c.log.Info("mfa audit event",
			zap.String("event", "mfa.verification_succeeded"),
			zap.String("user", username),
			zap.String("remote_address", remoteAddress(conn)),
			zap.String("factor", factorName),
		)
		markAuthenticated(sctx)
		return primaryPerms, nil
	}
}

// verifyPrompt is the single-line prompt shown to enrolled users.
func (c *Config) verifyPrompt() string {
	return "Authenticator code (or recovery code prefixed with r-): "
}

// verifyAndCommit tries the response against each configured factor,
// using the latest enrollment record while the per-user storage lock
// is held. Access is granted only after replay-sensitive factor state
// and success bookkeeping are durably persisted.
func (c *Config) verifyAndCommit(ctx context.Context, username, response string) (bool, string, error) {
	var accepted bool
	var factorName string
	var verifyErr error

	err := c.store.Update(ctx, c.serverName, username, func(rec *EnrollmentRecord) *EnrollmentRecord {
		if rec == nil || !rec.Enrolled() {
			verifyErr = errors.New("mfa: enrollment changed during verification")
			return nil
		}
		if c.Policy.LockedOut(rec, time.Now()) {
			verifyErr = &LockoutError{Until: rec.FailedAttempts.LockedUntil}
			return nil
		}

		var updated FactorBlob
		accepted, factorName, updated, verifyErr = c.verifyResponse(ctx, rec, response)
		if verifyErr != nil || !accepted {
			return nil
		}
		if updated != nil {
			encoded, err := json.Marshal(updated)
			if err != nil {
				verifyErr = fmt.Errorf("mfa: encoding %q state: %w", factorName, err)
				accepted = false
				return nil
			}
			rec.Factors[factorName] = encoded
		}
		rec.FailedAttempts = FailedAttempts{}
		rec.LastUsedAt = time.Now()
		return rec
	})
	if err != nil {
		return false, "", fmt.Errorf("mfa: persisting verification: %w", err)
	}
	if verifyErr != nil {
		return false, "", verifyErr
	}
	return accepted, factorName, nil
}

// verifyResponse tries the response against each configured factor,
// preferring the recovery factor when the response has the r- prefix.
// Returns (ok, factorName, updatedBlob, err).
func (c *Config) verifyResponse(ctx context.Context, rec *EnrollmentRecord, response string) (bool, string, FactorBlob, error) {
	order := c.VerifyPreference
	if strings.HasPrefix(response, "r-") || strings.HasPrefix(response, "-r") {
		order = prependIfMissing(order, "recovery_codes")
		response = strings.TrimPrefix(strings.TrimPrefix(response, "r-"), "-r")
	}

	username := rec.Username
	for _, name := range order {
		factor := c.factors[name]
		if factor == nil {
			continue
		}
		raw, ok := rec.Factors[name]
		if !ok {
			continue
		}
		blob, err := unmarshalBlob(factor, raw)
		if err != nil {
			return false, name, nil, fmt.Errorf("mfa: decoding %q blob: %w", name, err)
		}
		accepted, updated, err := factor.Verify(ctx, username, blob, response)
		if err != nil {
			return false, name, nil, err
		}
		if accepted {
			return true, name, updated, nil
		}
	}
	return false, "", nil, nil
}

// registerFailure atomically increments the failure counter using
// the configured policy and applies the lockout transition. Errors
// are logged but not surfaced — the caller has already decided the
// verification failed.
func (c *Config) registerFailure(sctx session.Context, username string) {
	now := time.Now()
	var lockoutStarted bool
	var lockedUntil time.Time
	err := c.store.Update(sctx, c.serverName, username, func(cur *EnrollmentRecord) *EnrollmentRecord {
		if cur == nil {
			// No record — nothing to write. Callers should not have
			// entered verify without a record, but be tolerant.
			return nil
		}
		wasLocked := !cur.FailedAttempts.LockedUntil.IsZero() && now.Before(cur.FailedAttempts.LockedUntil)
		cur.FailedAttempts = c.Policy.NextLockoutState(cur.FailedAttempts, now)
		lockoutStarted = !wasLocked && now.Before(cur.FailedAttempts.LockedUntil)
		lockedUntil = cur.FailedAttempts.LockedUntil
		return cur
	})
	if err != nil {
		c.log.Warn("mfa: recording failure",
			zap.String("user", username),
			zap.Error(err),
		)
		return
	}
	if lockoutStarted {
		remote := ""
		if sctx.RemoteAddr() != nil {
			remote = sctx.RemoteAddr().String()
		}
		c.log.Warn("mfa audit event",
			zap.String("event", "mfa.lockout_started"),
			zap.String("user", username),
			zap.String("remote_address", remote),
			zap.Time("locked_until", lockedUntil),
		)
	}
}

// ------------------------------------------------------------------
// Enrollment challenge — used when the user is unenrolled and the
// grace period has elapsed (ModeRequire). Runs the setup wizard over
// keyboard-interactive as the second "method".

func (c *Config) enrollmentChallenge(sctx session.Context, primaryPerms *gossh.Permissions) func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		username := UsernameFromCtx(sctx)
		if username == "" {
			return nil, errors.New("mfa: no username during enrollment")
		}

		// Locate the required factors.
		totp := c.factors["totp"]
		if totp == nil {
			return nil, errors.New("mfa: totp factor is not configured")
		}
		recovery := c.factors["recovery_codes"] // optional

		// Enroll TOTP first: generate secret + otpauth URI.
		totpBlob, totpArtifact, err := totp.Enroll(sctx, username)
		if err != nil {
			return nil, fmt.Errorf("mfa: generating totp: %w", err)
		}

		// Round 1: instructional banner (no questions).
		intro := buildEnrollmentIntro(username, totpArtifact)
		if _, err := challenge(username, intro, nil, nil); err != nil {
			return nil, err
		}

		// Round 2: prompt for the verification code.
		answers, err := challenge(
			username,
			"Enter the 6-digit code from your authenticator to confirm enrollment.",
			[]string{"Verification code: "},
			[]bool{false},
		)
		if err != nil {
			return nil, err
		}
		if len(answers) != 1 {
			return nil, errors.New("mfa: expected one answer")
		}
		ok, verifiedTOTPBlob, err := totp.Verify(sctx, username, totpBlob, strings.TrimSpace(answers[0]))
		if err != nil {
			return nil, fmt.Errorf("mfa: verifying totp during enrollment: %w", err)
		}
		if !ok {
			return nil, errors.New("mfa: verification code did not match; enrollment aborted")
		}
		if verifiedTOTPBlob != nil {
			totpBlob = verifiedTOTPBlob
		}

		// Enroll recovery codes if available.
		var recoveryBlob FactorBlob
		var recoveryArtifact EnrollmentArtifact
		if recovery != nil {
			recoveryBlob, recoveryArtifact, err = recovery.Enroll(sctx, username)
			if err != nil {
				c.log.Warn("mfa: generating recovery codes",
					zap.String("user", username),
					zap.Error(err),
				)
				// Non-fatal: continue with TOTP-only enrollment. The
				// user must reset and re-enroll to generate codes.
				recovery = nil
			}
		}

		totpJSON, err := json.Marshal(totpBlob)
		if err != nil {
			return nil, fmt.Errorf("mfa: encoding totp enrollment: %w", err)
		}
		var recoveryJSON json.RawMessage
		if recovery != nil && recoveryBlob != nil {
			recoveryJSON, err = json.Marshal(recoveryBlob)
			if err != nil {
				return nil, fmt.Errorf("mfa: encoding recovery enrollment: %w", err)
			}
		}

		now := time.Now()
		var enrollmentConflict bool
		saveErr := c.store.Update(sctx, c.serverName, username, func(cur *EnrollmentRecord) *EnrollmentRecord {
			if cur.Enrolled() {
				enrollmentConflict = true
				return nil
			}
			if cur == nil {
				cur = &EnrollmentRecord{}
			}
			cur.EnrolledAt = now
			cur.Factors = map[string]json.RawMessage{"totp": totpJSON}
			if recoveryJSON != nil {
				cur.Factors["recovery_codes"] = recoveryJSON
			}
			cur.FailedAttempts = FailedAttempts{}
			return cur
		})
		if saveErr != nil {
			return nil, fmt.Errorf("mfa: persisting enrollment: %w", saveErr)
		}
		if enrollmentConflict {
			return nil, errors.New("mfa: enrollment changed during setup")
		}

		// Round 3: display recovery codes if any, then confirm.
		if recovery != nil && len(recoveryArtifact.Codes) > 0 {
			msg := buildRecoveryCodesMessage(recoveryArtifact.Codes)
			if _, err := challenge(username, msg, []string{"Press Enter to continue: "}, []bool{true}); err != nil {
				return nil, err
			}
		}

		c.log.Info("mfa audit event",
			zap.String("event", "mfa.enrollment_created"),
			zap.String("user", username),
			zap.String("remote_address", remoteAddress(conn)),
		)
		markAuthenticated(sctx)
		return primaryPerms, nil
	}
}

func buildEnrollmentIntro(username string, art EnrollmentArtifact) string {
	var b strings.Builder
	b.WriteString("Multi-factor authentication setup\r\n")
	b.WriteString("---------------------------------\r\n")
	if art.Instructions != "" {
		b.WriteString(art.Instructions)
		if !strings.HasSuffix(art.Instructions, "\n") {
			b.WriteString("\r\n")
		}
	}
	if art.OtpauthURI != "" {
		b.WriteString("\r\nURI:  ")
		b.WriteString(art.OtpauthURI)
		b.WriteString("\r\n")
	}
	if art.QRCode != "" {
		b.WriteString("\r\n")
		b.WriteString(art.QRCode)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\nAfter adding the account to your authenticator app, enter the 6-digit code on the next prompt.\r\n")
	return b.String()
}

func buildRecoveryCodesMessage(codes []string) string {
	var b strings.Builder
	b.WriteString("Recovery codes\r\n")
	b.WriteString("--------------\r\n")
	b.WriteString("Save these codes somewhere safe. Each code works once and can be used in place of a TOTP code, prefixed with 'r-':\r\n\r\n")
	for _, c := range codes {
		b.WriteString("  ")
		b.WriteString(c)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// unmarshalBlob decodes the persisted JSON blob into a fresh instance
// produced by the factor. Factors are expected to return an
// unmarshallable value (a struct or *struct) from Enroll.
func unmarshalBlob(factor SecondFactor, raw json.RawMessage) (FactorBlob, error) {
	if bh, ok := factor.(interface {
		NewBlob() FactorBlob
	}); ok {
		blob := bh.NewBlob()
		if err := json.Unmarshal(raw, &blob); err != nil {
			return nil, err
		}
		return blob, nil
	}
	// Fallback: decode into a generic map. Individual factors are
	// expected to accept map[string]any in Verify, but the sanctioned
	// path is to implement NewBlob().
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func prependIfMissing(list []string, item string) []string {
	for _, v := range list {
		if v == item {
			return list
		}
	}
	out := make([]string, 0, len(list)+1)
	out = append(out, item)
	return append(out, list...)
}

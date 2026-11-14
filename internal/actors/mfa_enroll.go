// Package actors: enrollment wizard actor for MFA.
//
// The mfa_enroll actor is intended to be paired with the
// ssh.actor_matchers.mfa_status matcher (typically statuses:
// ["unenrolled", "pending"]) and marked Final so it terminates the
// session after enrollment completes.
//
// Unlike the auth-time keyboard-interactive enrollment flow, the
// actor runs inside an SSH channel, which lets it render the full
// terminal-friendly QR code and display the recovery codes clearly.
package actors

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication/mfa"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MFAEnroll{})
}

// MFAEnroll is an actor that walks the user through TOTP + recovery
// code enrollment inside an SSH session. Registered as
// ssh.actors.mfa_enroll.
type MFAEnroll struct {
	// Message is an optional greeting shown before the wizard begins.
	Message string `json:"message,omitempty"`

	// SkipWhenEnrolled, when true, exits cleanly instead of
	// re-enrolling if the user already has a record. Default true.
	SkipWhenEnrolled *bool `json:"skip_when_enrolled,omitempty"`

	logger *zap.Logger
}

// CaddyModule identifies the module to Caddy.
func (MFAEnroll) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actors.mfa_enroll",
		New: func() caddy.Module { return new(MFAEnroll) },
	}
}

// Provision applies defaults.
func (a *MFAEnroll) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	if a.SkipWhenEnrolled == nil {
		v := true
		a.SkipWhenEnrolled = &v
	}
	return nil
}

// Handle implements session.Handler.
func (a MFAEnroll) Handle(sess session.Session) error {
	cfg := mfa.ConfigFromCtx(sess.Context())
	if cfg == nil {
		writeLine(sess, "MFA is not configured on this server.")
		return errors.New("mfa_enroll: no mfa.Config on session context")
	}
	username := mfa.UsernameFromCtx(sess.Context())
	if username == "" {
		writeLine(sess, "MFA enrollment requires an authenticated username.")
		return errors.New("mfa_enroll: session has no canonical username")
	}

	// Load the current record so we know whether to skip.
	ctx := context.Background()
	rec, _, err := cfg.Store().Load(ctx, cfg.ServerName(), username)
	if err != nil {
		a.logger.Error("mfa_enroll: loading record", zap.Error(err))
		writeLine(sess, "Unable to read MFA state right now. Please try again later.")
		return err
	}
	if rec.Enrolled() && a.SkipWhenEnrolled != nil && *a.SkipWhenEnrolled {
		writeLine(sess, "MFA is already enrolled for this account. Use `kadeessh mfa reset` (as admin) to re-enroll.")
		return nil
	}

	totp := cfg.Factor("totp")
	if totp == nil {
		writeLine(sess, "TOTP factor is not enabled on this server.")
		return errors.New("mfa_enroll: totp factor unavailable")
	}
	recovery := cfg.Factor("recovery_codes") // optional

	if a.Message != "" {
		writeLine(sess, a.Message)
	}
	writeLine(sess, "Multi-factor authentication setup")
	writeLine(sess, "---------------------------------")

	// Generate TOTP credentials.
	totpBlob, totpArtifact, err := totp.Enroll(ctx, username)
	if err != nil {
		a.logger.Error("mfa_enroll: totp enroll", zap.Error(err))
		writeLine(sess, "Failed to generate TOTP credentials. Please contact your administrator.")
		return err
	}
	if totpArtifact.Instructions != "" {
		writeLine(sess, totpArtifact.Instructions)
	}
	if totpArtifact.QRCode != "" {
		writeLine(sess, "")
		_, _ = io.WriteString(sess, totpArtifact.QRCode)
		writeLine(sess, "")
	}
	if totpArtifact.OtpauthURI != "" {
		writeLine(sess, "URI: "+totpArtifact.OtpauthURI)
	}
	writeLine(sess, "")

	// Prompt for confirmation code. Two attempts are allowed before
	// giving up, since typos on hand-entered secrets are common.
	confirmed := false
	reader := bufio.NewReader(sess)
	for attempt := 1; attempt <= 3; attempt++ {
		_, _ = io.WriteString(sess, fmt.Sprintf("Enter the 6-digit code from your authenticator to confirm (%d/3): ", attempt))
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		code := strings.TrimSpace(line)
		ok, verifiedTOTPBlob, err := totp.Verify(ctx, username, totpBlob, code)
		if err != nil {
			a.logger.Warn("mfa_enroll: verify errored", zap.Error(err))
			writeLine(sess, "Unable to verify the code right now. Please try again later.")
			return err
		}
		if ok {
			if verifiedTOTPBlob != nil {
				totpBlob = verifiedTOTPBlob
			}
			confirmed = true
			break
		}
		writeLine(sess, "  That code did not match. Please try again.")
	}
	if !confirmed {
		writeLine(sess, "Enrollment cancelled. No changes have been saved.")
		return errors.New("mfa_enroll: user failed to confirm code")
	}

	// Generate recovery codes if available.
	var recoveryBlob mfa.FactorBlob
	var recoveryArtifact mfa.EnrollmentArtifact
	if recovery != nil {
		recoveryBlob, recoveryArtifact, err = recovery.Enroll(ctx, username)
		if err != nil {
			a.logger.Warn("mfa_enroll: recovery enroll", zap.Error(err))
			recovery = nil // continue without recovery codes
		}
	}

	totpJSON, err := json.Marshal(totpBlob)
	if err != nil {
		return fmt.Errorf("mfa_enroll: encoding totp enrollment: %w", err)
	}
	var recoveryJSON json.RawMessage
	if recovery != nil && recoveryBlob != nil {
		recoveryJSON, err = json.Marshal(recoveryBlob)
		if err != nil {
			return fmt.Errorf("mfa_enroll: encoding recovery enrollment: %w", err)
		}
	}

	var enrollmentConflict bool
	var enrollmentReplaced bool
	saveErr := cfg.Store().Update(ctx, cfg.ServerName(), username, func(cur *mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
		if cur.Enrolled() && a.SkipWhenEnrolled != nil && *a.SkipWhenEnrolled {
			enrollmentConflict = true
			return nil
		}
		enrollmentReplaced = cur.Enrolled()
		if cur == nil {
			cur = &mfa.EnrollmentRecord{}
		}
		cur.EnrolledAt = time.Now()
		cur.Factors = map[string]json.RawMessage{"totp": totpJSON}
		if recoveryJSON != nil {
			cur.Factors["recovery_codes"] = recoveryJSON
		}
		cur.FailedAttempts = mfa.FailedAttempts{}
		return cur
	})
	if saveErr != nil {
		a.logger.Error("mfa_enroll: saving record", zap.Error(saveErr))
		writeLine(sess, "Enrollment could not be saved. Please try again later.")
		return saveErr
	}
	if enrollmentConflict {
		writeLine(sess, "MFA enrollment changed during setup. No credentials were replaced.")
		return errors.New("mfa_enroll: enrollment changed during setup")
	}

	writeLine(sess, "")
	writeLine(sess, "MFA enrollment complete.")
	remoteAddress := ""
	if sess.RemoteAddr() != nil {
		remoteAddress = sess.RemoteAddr().String()
	}
	event := "mfa.enrollment_created"
	if enrollmentReplaced {
		event = "mfa.enrollment_replaced"
	}
	a.logger.Info("mfa audit event",
		zap.String("event", event),
		zap.String("user", username),
		zap.String("remote_address", remoteAddress),
	)

	if recovery != nil && len(recoveryArtifact.Codes) > 0 {
		writeLine(sess, "")
		writeLine(sess, "Recovery codes (save these somewhere safe — each can be used once, prefix with 'r-'):")
		for _, c := range recoveryArtifact.Codes {
			writeLine(sess, "  "+c)
		}
	}
	writeLine(sess, "")
	writeLine(sess, "You will be prompted for a code from your authenticator app on your next connection.")
	return nil
}

// writeLine writes s and a CRLF suffix to sess. Errors are ignored;
// caller flow-control is based on Read from the client side.
func writeLine(sess session.Session, s string) {
	_, _ = io.WriteString(sess, s+"\r\n")
}

var (
	_ caddy.Module      = (*MFAEnroll)(nil)
	_ caddy.Provisioner = (*MFAEnroll)(nil)
	_ session.Handler   = (*MFAEnroll)(nil)
)

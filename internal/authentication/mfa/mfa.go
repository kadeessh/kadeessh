package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(Config{})
}

// SetAuthenticatedUsername records the canonical identity returned by
// the primary authentication provider. Keeping an MFA-owned key avoids
// an import cycle while preserving Go context-key type safety.
func SetAuthenticatedUsername(ctx session.Context, username string) {
	state := stateForSession(ctx)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.username = username
}

// UsernameFromCtx returns the canonical identity recorded after primary
// authentication. It deliberately does not fall back to the
// client-controlled SSH username.
func UsernameFromCtx(ctx context.Context) string {
	return stateFromContext(ctx).snapshot().username
}

// Config is the MFA orchestrator. Registered under
// ssh.authentication.mfa; loaded from authentication.Config.MFARaw.
type Config struct {
	// Policy governs enforcement (grace period, sk-* handling,
	// rate-limit thresholds). Zero values are replaced with defaults
	// at provision time.
	Policy Policy `json:"policy,omitempty"`

	// StoreRaw is the pluggable persistence layer. If nil, defaults
	// to {"backend":"caddy"} — the Caddy-storage backed store.
	StoreRaw json.RawMessage `json:"store,omitempty" caddy:"namespace=ssh.authentication.mfa.stores inline_key=backend"`

	// FactorsRaw is the set of second-factor modules keyed by module
	// name (e.g. {"totp": {}, "recovery_codes": {}}). Defaults to
	// {"totp": {}, "recovery_codes": {}} when nil.
	FactorsRaw caddy.ModuleMap `json:"factors,omitempty" caddy:"namespace=ssh.authentication.mfa.factors"`

	// VerifyPreference orders which factors are tried first for a
	// given response. The first factor that accepts the response
	// (its Verify returns ok=true) wins. Responses with a leading
	// "r-" or "-r" prefix are routed to "recovery_codes" first,
	// regardless of this order. Defaults to ["totp",
	// "recovery_codes"].
	VerifyPreference []string `json:"verify_preference,omitempty"`

	// serverName captures the SSH server name so records can be
	// scoped. It is populated by BindServer() before use.
	serverName string

	store   EnrollmentStore
	factors map[string]SecondFactor
	log     *zap.Logger
	service *Service
}

// CaddyModule identifies this module to Caddy.
func (Config) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.mfa",
		New: func() caddy.Module { return new(Config) },
	}
}

// BindServer records the SSH server name that owns this MFA config.
// authentication.Config invokes this before Provision so records are
// scoped correctly.
func (c *Config) BindServer(name string) { c.serverName = name }

// Provision applies defaults, loads the store and factor modules, and
// prepares the decorator for use.
func (c *Config) Provision(ctx caddy.Context) error {
	c.log = ctx.Logger(c)
	if err := ValidateScopeComponent("server", c.serverName); err != nil {
		return err
	}
	c.Policy.applyDefaults()
	if err := c.Policy.validate(); err != nil {
		return err
	}

	if c.StoreRaw == nil {
		c.StoreRaw = json.RawMessage(`{"backend": "caddy"}`)
	}
	storeIface, err := ctx.LoadModule(c, "StoreRaw")
	if err != nil {
		return fmt.Errorf("mfa: loading store module: %w", err)
	}
	store, ok := storeIface.(EnrollmentStore)
	if !ok {
		return fmt.Errorf("mfa: %T is not EnrollmentStore", storeIface)
	}
	c.store = store

	if c.FactorsRaw == nil {
		c.FactorsRaw = caddy.ModuleMap{
			"totp":           json.RawMessage(`{}`),
			"recovery_codes": json.RawMessage(`{}`),
		}
	}
	factorsIface, err := ctx.LoadModule(c, "FactorsRaw")
	if err != nil {
		return fmt.Errorf("mfa: loading factor modules: %w", err)
	}
	c.factors = make(map[string]SecondFactor)
	sealKey := c.store.SealKey()
	for name, mod := range factorsIface.(map[string]any) {
		sf, ok := mod.(SecondFactor)
		if !ok {
			return fmt.Errorf("mfa: factor %q (%T) does not implement SecondFactor", name, mod)
		}
		if skr, ok := sf.(SealKeyReceiver); ok {
			skr.SetSealKey(sealKey)
		}
		c.factors[name] = sf
	}

	if len(c.VerifyPreference) == 0 {
		c.VerifyPreference = []string{"totp", "recovery_codes"}
	}
	c.service = newService(c.Policy, c.store, c.serverName)
	return nil
}

// Store returns the provisioned enrollment store. Exposed for the
// enrollment actor and admin CLI.
func (c *Config) Store() EnrollmentStore { return c.store }

// Factor returns a registered second-factor module by name, or nil.
func (c *Config) Factor(name string) SecondFactor { return c.factors[name] }

// ServerName returns the SSH server name this config is bound to.
func (c *Config) ServerName() string { return c.serverName }

// ------------------------------------------------------------------
// Callback wrappers used by authentication.Config to compose MFA with
// each primary flow.

// wrappedPasswordCallback is the signature of gossh's PasswordCallback.
type wrappedPasswordCallback func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error)

// wrappedPublicKeyCallback is the signature of gossh's PublicKeyCallback.
type wrappedPublicKeyCallback func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error)

// wrappedInteractiveCallback is the signature of gossh's KeyboardInteractiveCallback.
type wrappedInteractiveCallback func(conn gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error)

// WrapPassword decorates a password-flow callback with MFA.
func (c *Config) WrapPassword(ctx session.Context, inner wrappedPasswordCallback) wrappedPasswordCallback {
	if c == nil || inner == nil {
		return inner
	}
	return func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		perms, err := inner(conn, password)
		if err != nil {
			return perms, err
		}
		return c.continueAuthentication(ctx, conn, perms, FlowPassword, nil)
	}
}

// WrapPublicKey decorates a public-key-flow callback with MFA.
func (c *Config) WrapPublicKey(ctx session.Context, inner wrappedPublicKeyCallback) wrappedPublicKeyCallback {
	if c == nil || inner == nil {
		return inner
	}
	return func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		perms, err := inner(conn, key)
		if err != nil {
			return perms, err
		}
		return c.continueAuthentication(ctx, conn, perms, FlowPublicKey, key)
	}
}

// WrapInteractive decorates an interactive-flow callback with MFA.
// Because keyboard-interactive is also the transport for the second
// factor, we must be careful: if the interactive flow granted primary
// success but the client is expecting more rounds via the same
// channel, we cannot re-issue keyboard-interactive as the "next"
// method — the SSH client is already inside a KI round. In practice
// this collision is rare (deployments either use interactive as sole
// primary, or use publickey/password as primary with KI reserved for
// MFA). We handle the primary-KI case by finishing MFA inline within
// the same challenge sequence when possible; otherwise the primary
// KI flow is required to be terminal (no PartialSuccess).
func (c *Config) WrapInteractive(ctx session.Context, inner wrappedInteractiveCallback) wrappedInteractiveCallback {
	if c == nil || inner == nil {
		return inner
	}
	return func(conn gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		perms, err := inner(conn, client)
		if err != nil {
			return perms, err
		}
		return c.continueAuthentication(ctx, conn, perms, FlowInteractive, nil)
	}
}

// continueAuthentication adapts the service decision to SSH callbacks.
func (c *Config) continueAuthentication(sctx session.Context, conn gossh.ConnMetadata, primaryPerms *gossh.Permissions, flow PrimaryFlow, key gossh.PublicKey) (*gossh.Permissions, error) {
	username := UsernameFromCtx(sctx)
	service := c.service
	if service == nil {
		service = newService(c.Policy, c.store, c.serverName)
	}
	keyType := ""
	if key != nil {
		keyType = key.Type()
	}
	decision, err := service.Decide(context.Background(), AuthEvent{
		Username:          username,
		Flow:              flow,
		PrimaryKeyType:    keyType,
		PrimaryKeyNoTouch: allowsNoTouch(key, primaryPerms),
	})
	setDecision(sctx, c, flow, decision)
	if err != nil {
		var lockout *LockoutError
		switch {
		case errors.As(err, &lockout):
			c.log.Info("mfa audit event",
				zap.String("event", "mfa.lockout_denied"),
				zap.String("user", username),
				zap.String("remote_address", remoteAddress(conn)),
				zap.Time("locked_until", lockout.Until),
			)
			return nil, lockout
		case errors.Is(err, errEnrollmentStorage):
			c.log.Error("mfa: evaluating enrollment state",
				zap.String("user", username),
				zap.Error(err),
			)
			return nil, errors.New("mfa: storage error")
		default:
			return nil, err
		}
	}

	switch decision.Action {
	case ActionAllow:
		switch decision.Reason {
		case ReasonPrimaryFactor:
			markAuthenticated(sctx)
			c.log.Info("mfa audit event",
				zap.String("event", "mfa.sk_bypass"),
				zap.String("user", username),
				zap.String("remote_address", remoteAddress(conn)),
				zap.String("key_type", decision.PrimaryKeyType),
				zap.String("key_fingerprint", gossh.FingerprintSHA256(key)),
			)
		case ReasonGracePeriod:
			c.log.Warn("mfa audit event",
				zap.String("event", "mfa.grace_bypass"),
				zap.String("user", username),
				zap.String("remote_address", remoteAddress(conn)),
				zap.Time("enrollment_deadline", decision.EnrollmentDeadline),
			)
		default:
			return nil, fmt.Errorf("mfa: unsupported allow reason %q", decision.Reason)
		}
		return primaryPerms, nil
	case ActionVerify:
		return nil, &gossh.PartialSuccessError{
			Next: gossh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: c.verifyChallenge(sctx, primaryPerms),
			},
		}
	case ActionEnroll:
		return nil, &gossh.PartialSuccessError{
			Next: gossh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: c.enrollmentChallenge(sctx, primaryPerms),
			},
		}
	default:
		return nil, fmt.Errorf("mfa: unsupported decision action %d", decision.Action)
	}
}

func remoteAddress(conn gossh.ConnMetadata) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func allowsNoTouch(key gossh.PublicKey, perms *gossh.Permissions) bool {
	if hasPermission(perms, "no-touch-required") {
		return true
	}
	cert, ok := key.(*gossh.Certificate)
	return ok && hasPermission(&cert.Permissions, "no-touch-required")
}

func hasPermission(perms *gossh.Permissions, name string) bool {
	if perms == nil {
		return false
	}
	if _, ok := perms.Extensions[name]; ok {
		return true
	}
	_, ok := perms.CriticalOptions[name]
	return ok
}

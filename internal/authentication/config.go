package authentication

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	gossh "golang.org/x/crypto/ssh"
)

// Config holds the configuration of the various authentication flows, including
// allow/deny users/groups.
type Config struct {
	AllowUsers  []string        `json:"allow_users,omitempty"`
	allowUsers  map[string]bool `json:"-"`
	DenyUsers   []string        `json:"deny_users,omitempty"`
	denyUsers   map[string]bool `json:"-"`
	AllowGroups []string        `json:"allow_groups,omitempty"`
	allowGroups map[string]bool `json:"-"`
	DenyGroups  []string        `json:"deny_groups,omitempty"`
	denyGroups  map[string]bool `json:"-"`

	// UsernamePassword holds the configuration of the password-based
	// authentication flow. nil value disables the authentication flow.
	UsernamePassword *PasswordAuthFlow `json:"username_password,omitempty"`

	// PublicKey holds the configuration of the public-key-based
	// authentication flow. nil value disables the authentication flow.
	PublicKey *PublicKeyFlow `json:"public_key,omitempty"`

	// Interactive holds the configuration of the interactive-based
	// authentication flow. nil value disables the authentication flow.
	Interactive *InteractiveFlow `json:"interactive,omitempty"`
}

// Provision sets up the allowed/denied users/groups and provisions the non-nil authentication flows
func (c *Config) Provision(ctx caddy.Context) error {
	if c == nil {
		return nil
	}

	// Source: https://linux.die.net/man/5/sshd_config
	// "The allow/deny directives are processed in the following order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups."
	c.allowUsers, c.allowGroups, c.denyUsers, c.denyGroups = make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for _, v := range c.AllowUsers {
		c.allowUsers[v] = true
	}
	for _, v := range c.DenyUsers {
		c.denyUsers[v] = true
	}
	for _, v := range c.AllowGroups {
		c.allowGroups[v] = true
	}
	for _, v := range c.DenyGroups {
		c.denyGroups[v] = true
	}

	if c.UsernamePassword != nil {
		if err := c.UsernamePassword.Provision(ctx); err != nil {
			return err
		}
	}
	if c.PublicKey != nil {
		if err := c.PublicKey.Provision(ctx); err != nil {
			return err
		}
	}
	if c.Interactive != nil {
		if err := c.Interactive.Provision(ctx); err != nil {
			return err
		}
	}
	return nil
}

// PasswordCallback returns an authentiction callback conforming to the password callback func needed
// by ServerConfig of golang.org/x/crypto/ssh. The method returns nil if the field UsernamePassword
// is nil to disable password authentication.
func (c Config) PasswordCallback(ctx session.Context) func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
	if c.UsernamePassword == nil {
		return nil
	}
	return func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		if subjectAllowedNotDenied(conn.User(), c.allowUsers, c.denyUsers) {
			perms, err := c.UsernamePassword.callback(ctx)(conn, password)
			if err != nil {
				return perms, err
			}
			if u, ok := ctx.Value(UserCtxKey).(User); ok && u != nil {
				if !groupAllowedNotDenied(u.Groups(), c.allowGroups, c.denyGroups) {
					return nil, invalidCredentials
				}
			}
			return perms, nil
		}
		return nil, invalidCredentials
	}
}

// PublicKeyCallback returns an authentiction callback conforming to the public key authentication callback func needed
// by ServerConfig of golang.org/x/crypto/ssh. The method returns nil if the field PublicKey
// is nil to disable public key authentication.
func (c Config) PublicKeyCallback(ctx session.Context) func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	if c.PublicKey == nil {
		return nil
	}
	return func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if subjectAllowedNotDenied(conn.User(), c.allowUsers, c.denyUsers) {
			perms, err := c.PublicKey.callback(ctx)(conn, key)
			if err != nil {
				return perms, err
			}
			if u, ok := ctx.Value(UserCtxKey).(User); ok && u != nil {
				if !groupAllowedNotDenied(u.Groups(), c.allowGroups, c.denyGroups) {
					return nil, invalidCredentials
				}
			}
			return perms, nil
		}
		return nil, invalidCredentials
	}
}

// InteractiveCallback returns an authentiction callback conforming to the interactive authentication callback func needed
// by ServerConfig of golang.org/x/crypto/ssh. The method returns nil if the field Interactive is nil to disable interactive authentication.
func (c Config) InteractiveCallback(ctx session.Context) func(conn gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
	if c.Interactive == nil {
		return nil
	}
	return func(conn gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		if subjectAllowedNotDenied(conn.User(), c.allowUsers, c.denyUsers) {
			perms, err := c.Interactive.callback(ctx)(conn, client)
			if err != nil {
				return perms, err
			}
			if u, ok := ctx.Value(UserCtxKey).(User); ok && u != nil {
				if !groupAllowedNotDenied(u.Groups(), c.allowGroups, c.denyGroups) {
					return nil, invalidCredentials
				}
			}
			return perms, nil
		}
		return nil, invalidCredentials
	}
}

func subjectAllowedNotDenied(subject string, allowlist, denylist map[string]bool) bool {
	return (len(denylist) == 0 || !denylist[subject]) &&
		// if the list contains more than 0 entries and the user is in the list;
		// or the list is not specified then all users are checked.
		((len(allowlist) > 0 &&
			allowlist[subject]) ||
			(len(allowlist) == 0))
}

func groupAllowedNotDenied(groups []Group, allowlist, denylist map[string]bool) bool {
	for _, group := range groups {
		if !subjectAllowedNotDenied(group.Name(), allowlist, denylist) {
			return false
		}
	}
	return true
}

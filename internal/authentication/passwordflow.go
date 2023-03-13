package authentication

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"

	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

var _ caddy.Provisioner = (*PasswordAuthFlow)(nil)

func init() {
	caddy.RegisterModule(PasswordAuthFlow{})
}

// // PasswordAuthFlow holds the password-based authentication providers
type PasswordAuthFlow struct {
	authenticatorLogger `json:"-"`

	// A set of authentication providers implementing the UserPasswordAuthenticator interface. If none are specified,
	// all requests will always be unauthenticated.
	ProvidersRaw         caddy.ModuleMap                      `json:"providers,omitempty" caddy:"namespace=ssh.authentication.providers.password"`
	PermitEmptyPasswords bool                                 `json:"permit_empty_passwords,omitempty"`
	providers            map[string]UserPasswordAuthenticator `json:"-"`
	logger               *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (paf PasswordAuthFlow) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.authentication.flows.password_auth",
		New: func() caddy.Module {
			return new(PasswordAuthFlow)
		},
	}
}

// Provision sets up and loads the providers of conforming to UserPasswordAuthenticator interface
func (paf *PasswordAuthFlow) Provision(ctx caddy.Context) error {
	paf.logger = ctx.Logger(paf)
	paf.authenticatorLogger = authenticatorLogger{paf.logger}

	paf.providers = make(map[string]UserPasswordAuthenticator)
	mods, err := ctx.LoadModule(paf, "ProvidersRaw")
	if err != nil {
		return fmt.Errorf("loading authentication providers: %v", err)
	}
	for modName, modIface := range mods.(map[string]interface{}) {
		if pa, ok := modIface.(UserPasswordAuthenticator); ok {
			paf.providers[modName] = pa
			continue
		}
		return fmt.Errorf("%+v is not type UserPasswordAuthenticator", modIface)
	}
	return nil
}

func (paf PasswordAuthFlow) callback(ctx session.Context) func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		paf.authStart(conn, len(paf.providers), ctx.RemoteAddr())
		if !paf.PermitEmptyPasswords && len(password) == 0 {
			paf.invalidCredentials(conn)
			return nil, invalidCredentials
		}
		for name, auther := range paf.providers { //nolint:golint,misspell
			user, authed, err := auther.AuthenticateUser(conn, password)
			if err != nil {
				paf.authError(conn, name, err)
				continue
			}
			if !authed {
				paf.authFailed(conn, name)
				continue
			}
			paf.authSuccessful(conn, name, user)
			ctx.SetValue(UserCtxKey, user)
			return user.Permissions(), nil
		}
		paf.invalidCredentials(conn)
		return nil, invalidCredentials
	}
}

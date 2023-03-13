package authentication

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(InteractiveFlow{})
}

// InteractiveFlow holds the interactive authentication providers
type InteractiveFlow struct {
	authenticatorLogger
	// A set of authentication providers implementing the UserInteractiveAuthenticator interface. If none are specified,
	// all requests will always be unauthenticated.
	ProvidersRaw caddy.ModuleMap                         `json:"providers,omitempty" caddy:"namespace=ssh.providers.interactive"`
	providers    map[string]UserInteractiveAuthenticator `json:"-"`
	logger       *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (upf InteractiveFlow) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.authentication.flows.interactive",
		New: func() caddy.Module {
			return new(InteractiveFlow)
		},
	}
}

// Provision sets up and loads the providers of conforming to UserInteractiveAuthenticator interface
func (upf *InteractiveFlow) Provision(ctx caddy.Context) error {
	upf.logger = ctx.Logger(upf)
	upf.authenticatorLogger = authenticatorLogger{upf.logger}

	upf.providers = make(map[string]UserInteractiveAuthenticator)
	mods, err := ctx.LoadModule(upf, "ProvidersRaw")
	if err != nil {
		return fmt.Errorf("loading authentication providers: %v", err)
	}

	for modName, modIface := range mods.(map[string]interface{}) {
		if pa, ok := modIface.(UserInteractiveAuthenticator); ok {
			upf.providers[modName] = pa
			continue
		}
		return fmt.Errorf("%+v is not type UserInteractiveAuthenticator", modIface)
	}
	return nil
}

func (upf InteractiveFlow) callback(ctx session.Context) func(conn gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		upf.authStart(conn, len(upf.providers), ctx.RemoteAddr())
		for name, auther := range upf.providers { //nolint:golint,misspell
			user, authed, err := auther.AuthenticateUser(conn, client)
			if err != nil {
				upf.authError(conn, name, err)
				continue
			}
			if !authed {
				upf.authFailed(conn, name)
				continue
			}
			upf.authSuccessful(conn, name, user)
			ctx.SetValue(UserCtxKey, user)
			return user.Permissions(), nil
		}
		upf.invalidCredentials(conn)
		return nil, invalidCredentials
	}
}
